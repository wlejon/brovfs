#include "host_class.h"
#include "object_builder.h"

#include <unordered_map>

namespace brovfs::api {

namespace {

// One table per thread, keyed by the class object (host_class.h): the
// constructor and prototype a class holds are Persistents of the thread
// that installed it, so a second thread's realm gets a second, independent
// pair. Never freed — a thread's runtime lives until the thread does.
std::unordered_map<const HostClass*, HostClass::Slots>& threadSlots() {
    static thread_local std::unordered_map<const HostClass*, HostClass::Slots> t;
    return t;
}

struct BrandedHandle {
    static constexpr uint64_t kMagic = 0x42524F5646534843ULL; // "BROVFSHC"
    uint64_t magic = kMagic;
    const HostClass* cls = nullptr;
    void* data = nullptr;
    ev::HandleDestructor dtor = nullptr;
};

} // namespace

HostClass::Slots& HostClass::slots() const {
    return threadSlots()[this];
}

const HostClass::Slots* HostClass::slotsIfAny() const {
    auto& t = threadSlots();
    auto it = t.find(this);
    return it == t.end() ? nullptr : &it->second;
}

bool HostClass::installed() const {
    const Slots* s = slotsIfAny();
    return s && s->ctor;
}

void HostClass::install(const char* name, uint32_t arity, ev::NativeFn body,
                        const std::function<void(ObjectBuilder&)>& decorate) {
    ev::NativeFn ctorBody = body;
    if (!ctorBody) {
        std::string msg = std::string("TypeError: ") + name + " is not a constructor";
        ctorBody = [msg](Value, std::span<const Value>) { return ev::throwTypeError(msg); };
    }

    Slots& s = slots();
    delete s.ctor;
    delete s.proto;
    s.ctor = nullptr;
    s.proto = nullptr;

    ev::Persistent ctor(ev::makeFunction(std::move(ctorBody), arity, name));
    s.ctor = new ev::Persistent(ctor.get());

    {
        ObjectBuilder proto(ev::getProperty(ctor.get(), "prototype"));
        proto.set("constructor", ctor.get());
        if (decorate) decorate(proto);
        s.proto = new ev::Persistent(proto.get());
    }

    ev::registerGlobal(name, s.ctor->get());
    ev::GlobalValue gt = ev::globalValue("globalThis");
    if (gt.found && !gt.value.isUndefined() && ev::isObject(gt.value)) {
        ev::Persistent gtObj(gt.value);
        ev::setProperty(gtObj.get(), name, s.ctor->get());
    }
}

void HostClass::alias(const char* name) const {
    const Slots* s = slotsIfAny();
    if (!s || !s->ctor) return;
    ev::registerGlobal(name, s->ctor->get());
    ev::GlobalValue gt = ev::globalValue("globalThis");
    if (gt.found && !gt.value.isUndefined() && ev::isObject(gt.value)) {
        ev::Persistent gtObj(gt.value);
        ev::setProperty(gtObj.get(), name, s->ctor->get());
    }
}

void HostClass::inherit(const HostClass& base) const {
    const Slots* s = slotsIfAny();
    const Slots* b = base.slotsIfAny();
    if (!s || !s->proto || !b || !b->proto) return;
    ev::GlobalValue objectCtor = ev::globalValue("Object");
    if (!objectCtor.found || !ev::isObject(objectCtor.value)) return;
    ev::Persistent objectNs(objectCtor.value);
    ev::Persistent setProto(ev::getProperty(objectNs.get(), "setPrototypeOf"));
    if (!ev::isFunction(setProto.get())) return;
    const Value args[2] = {s->proto->get(), b->proto->get()};
    ev::call(setProto.get(), ev::undefined(), std::span<const Value>(args, 2));
}

Value HostClass::make(void* data, ev::HandleDestructor dtor, ev::Finalize when) const {
    auto* bh = new BrandedHandle{BrandedHandle::kMagic, this, data, dtor};
    auto wrapperDtor = +[](void* raw) {
        auto* b = static_cast<BrandedHandle*>(raw);
        if (b->dtor) b->dtor(b->data);
        b->magic = 0;
        delete b;
    };
    const Slots* s = slotsIfAny();
    if (!s || !s->proto) return ev::makeHandle(bh, wrapperDtor, when);
    return ev::makeHandle(bh, wrapperDtor, when, s->proto->get());
}

void* HostClass::unwrap(Value val) const {
    auto* bh = static_cast<BrandedHandle*>(ev::handleData(val));
    if (!bh || bh->magic != BrandedHandle::kMagic || bh->cls != this) return nullptr;
    return bh->data;
}

void HostClass::setStatic(const char* name, Value v) const {
    const Slots* s = slotsIfAny();
    if (!s || !s->ctor) return;
    ev::Persistent valP(v);
    s->ctor->set(ev::setProperty(s->ctor->get(), name, valP.get()));
}

Value HostClass::prototype() const {
    const Slots* s = slotsIfAny();
    return (s && s->proto) ? s->proto->get() : ev::undefined();
}

Value HostClass::constructor() const {
    const Slots* s = slotsIfAny();
    return (s && s->ctor) ? s->ctor->get() : ev::undefined();
}

} // namespace brovfs::api
