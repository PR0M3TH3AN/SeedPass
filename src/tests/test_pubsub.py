from seedpass.core.pubsub import PubSub


def test_subscribe_and_publish():
    bus = PubSub()
    calls = []

    def handler(arg):
        calls.append(arg)

    bus.subscribe("event", handler)
    bus.publish("event", 123)

    assert calls == [123]


def test_unsubscribe():
    bus = PubSub()
    calls = []

    def handler():
        calls.append(True)

    bus.subscribe("event", handler)
    bus.unsubscribe("event", handler)
    bus.publish("event")

    assert calls == []
