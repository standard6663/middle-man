from mitmproxy.addons import next_layer
from mitmproxy.addons import proxyserver
from mitmproxy.addons import save
from mitmproxy.addons import tlsconfig
from mitmproxy.addons import record


def default_addons():
    return [
        proxyserver.Proxyserver(),
        next_layer.NextLayer(),
        save.Save(),
        tlsconfig.TlsConfig(),
        record.Record()
    ]
