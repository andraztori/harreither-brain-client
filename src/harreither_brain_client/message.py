# Special value indicating that the message counter should be auto-filled
MC_AUTO = -1000


class MessageReceived:
    def __init__(self, type_int, mc, payload, ref=None) -> None:
        self.type_int = type_int
        self.mc = mc
        self.payload = payload
        self.ref = ref

    def __repr__(self):
        return (
            "MessageReceived(type_int="
            f"{self.type_int}, mc={self.mc}, payload={self.payload}, ref={self.ref})"
        )


class MessageSend:
    def __init__(self, type_int, mc=None, payload=None, ref=None) -> None:
        self.type_int = type_int
        self.mc = mc
        self.payload = payload
        self.ref = ref

    def __repr__(self):
        return (
            "MessageSend(type_int="
            f"{self.type_int}, mc={self.mc}, payload={self.payload}, ref={self.ref})"
        )
