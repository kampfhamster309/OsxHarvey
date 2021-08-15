subscribers = dict()


def subscribe(layer_name: str, fn):
    if layer_name not in subscribers:
        subscribers[layer_name] = []
    subscribers[layer_name].append(fn)


def post_event(layer_name: str, instance, data):
    if layer_name not in subscribers:
        return
    for fn in subscribers[layer_name]:
        fn(instance, data)
