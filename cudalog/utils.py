def trycast(new_type, value, default=None):
    try:
        return new_type(value)
    except:
        return default
