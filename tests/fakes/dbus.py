"""A D-Bus stand-in, so the *real* bless server can be tested without a radio.

The existing suite substitutes a fake BlessServer, which means everything bless
actually does - flag conversion, advertisement construction, the object paths -
is never exercised. That is how a hard crash on `extended-properties` and an
advertisement monkeypatch that had never once executed both shipped green.

Mocking one layer lower fixes that: bless runs unmodified, and only the
transport underneath it is fake. Every export and every method call is
recorded, so tests can assert on what bless *would have told BlueZ*.

Patch these two names, which bless imports into its server module:

    bless.backends.bluezdbus.server.MessageBus
    bless.backends.bluezdbus.server.get_adapter
"""

from __future__ import annotations


class FakeInterface:
    """Records the D-Bus calls bless makes on an adapter interface."""

    def __init__(self, name: str, recorder: "FakeAdapter"):
        self.name = name
        self._recorder = recorder

    def __getattr__(self, attr: str):
        # dbus_next exposes methods as call_<snake_case_name>. Accept any of
        # them so a bless version that calls something new fails on the
        # assertion in the test, not on an AttributeError here.
        if not attr.startswith("call_"):
            raise AttributeError(attr)

        async def call(*args, **kwargs):
            self._recorder.calls.append((self.name, attr, args))
            failure = self._recorder.fail_once.pop(attr, None)
            if failure is not None:
                raise failure
            return None

        return call


class FakeAdapter:
    """Stands in for the dbus_next ProxyObject bless gets from get_adapter."""

    def __init__(self, path: str = "/org/bluez/hci0"):
        self.path = path
        self.calls: list[tuple[str, str, tuple]] = []
        # method name -> exception, raised on the next call and then cleared.
        self.fail_once: dict[str, BaseException] = {}

    def get_interface(self, name: str) -> FakeInterface:
        return FakeInterface(name, self)

    def called(self, method: str) -> list[tuple]:
        return [args for _, m, args in self.calls if m == method]


class FakeBus:
    """Stands in for dbus_next's MessageBus.

    `exported` is the interesting part: it is how a test can tell that a failed
    advertisement registration left its object behind on the bus.
    """

    def __init__(self, bus_type=None):
        self.bus_type = bus_type
        self.exported: dict[str, object] = {}
        self.unexported: list[str] = []
        self.disconnected = False

    async def connect(self) -> "FakeBus":
        return self

    def export(self, path: str, obj: object) -> None:
        self.exported[path] = obj

    def unexport(self, path: str, obj: object | None = None) -> None:
        # bless calls this both ways: with the object (the app) and without
        # it (stop_advertising). Tolerate both.
        self.exported.pop(path, None)
        self.unexported.append(path)

    def disconnect(self) -> None:
        self.disconnected = True

    def exported_paths(self, contains: str = "") -> list[str]:
        return sorted(p for p in self.exported if contains in p)


def install(monkeypatch, adapter: FakeAdapter | None = None) -> tuple[FakeBus, FakeAdapter]:
    """Point bless's server module at the fakes. Returns (bus, adapter)."""
    import bless.backends.bluezdbus.server as server

    bus = FakeBus()
    adapter = adapter or FakeAdapter()

    class _BusFactory:
        def __init__(self, *a, **k):
            pass

        async def connect(self):
            return bus

    async def _get_adapter(_bus, name=None):
        adapter.requested_name = name
        return adapter

    monkeypatch.setattr(server, "MessageBus", _BusFactory)
    monkeypatch.setattr(server, "get_adapter", _get_adapter)
    return bus, adapter
