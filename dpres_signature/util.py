import six


def ensure_binary(text):
    """
    Encode given string to a byte string if it's Unicode or return
    it unchanged if it's a byte string
    """
    if isinstance(text, six.text_type):
        return text.encode("utf-8")
    elif isinstance(text, six.binary_type):
        return text
    else:
        raise TypeError("Expected a (byte) string, got {}".format(type(text)))


def ensure_text(text):
    """
    Encode given string to an Unicode string from UTF-8 if it's a byte string
    or return it unchanged if it's a byte string
    """
    if isinstance(text, six.binary_type):
        return text.decode("utf-8")
    elif isinstance(text, six.text_type):
        return text
    else:
        raise TypeError("Expected a (byte) string, got {}".format(type(text)))
