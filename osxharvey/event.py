subscribers = dict()


def subscribe(layer_name: str, fn):
    """
    Loads the subscriber dictionary
    """
    if layer_name not in subscribers:
        subscribers[layer_name] = []
    subscribers[layer_name].append(fn)


def post_event(layer_type: str, instance, data):
    """
    Publishes events for different packet layer types
    """
    if layer_type not in subscribers:
        return
    for fn in subscribers[layer_type]:
        fn(instance, data)
