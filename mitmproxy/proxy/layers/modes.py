from __future__ import annotations

import sys
from abc import ABCMeta

from mitmproxy.proxy import commands
from mitmproxy.proxy import events
from mitmproxy.proxy import layer
from mitmproxy.proxy.mode_specs import ReverseMode
from mitmproxy.proxy.utils import expect

if sys.version_info < (3, 11):
    from typing_extensions import assert_never
else:
    from typing import assert_never


class HttpProxy(layer.Layer):
    @expect(events.Start)
    def _handle_event(self, event: events.Event) -> layer.CommandGenerator[None]:
        child_layer = layer.NextLayer(self.context)
        self._handle_event = child_layer.handle_event
        yield from child_layer.handle_event(event)


class HttpUpstreamProxy(layer.Layer):
    @expect(events.Start)
    def _handle_event(self, event: events.Event) -> layer.CommandGenerator[None]:
        child_layer = layer.NextLayer(self.context)
        self._handle_event = child_layer.handle_event
        yield from child_layer.handle_event(event)


class DestinationKnown(layer.Layer, metaclass=ABCMeta):
    """Base layer for layers that gather connection destination info and then delegate."""

    child_layer: layer.Layer

    def finish_start(self) -> layer.CommandGenerator[str | None]:
        if (
            self.context.options.connection_strategy == "eager"
            and self.context.server.address
            and self.context.server.transport_protocol == "tcp"
        ):
            err = yield commands.OpenConnection(self.context.server)
            if err:
                self._handle_event = self.done  # type: ignore
                return err

        self._handle_event = self.child_layer.handle_event  # type: ignore
        yield from self.child_layer.handle_event(events.Start())
        return None

    @expect(events.DataReceived, events.ConnectionClosed)
    def done(self, _) -> layer.CommandGenerator[None]:
        yield from ()


class ReverseProxy(DestinationKnown):
    @expect(events.Start)
    def _handle_event(self, event: events.Event) -> layer.CommandGenerator[None]:
        spec = self.context.client.proxy_mode
        assert isinstance(spec, ReverseMode)
        self.context.server.address = spec.address

        self.child_layer = layer.NextLayer(self.context)

        # For secure protocols, set SNI if keep_host_header is false
        match spec.scheme:
            case "http3" | "quic" | "https" | "tls" | "dtls":
                if not self.context.options.keep_host_header:
                    self.context.server.sni = spec.address[0]
            case "tcp" | "http" | "udp" | "dns":
                pass
            case _:  # pragma: no cover
                assert_never(spec.scheme)

        err = yield from self.finish_start()
        if err:
            yield commands.CloseConnection(self.context.client)


class TransparentProxy(DestinationKnown):
    @expect(events.Start)
    def _handle_event(self, event: events.Event) -> layer.CommandGenerator[None]:
        assert self.context.server.address, "No server address set."
        self.child_layer = layer.NextLayer(self.context)
        err = yield from self.finish_start()
        if err:
            yield commands.CloseConnection(self.context.client)
