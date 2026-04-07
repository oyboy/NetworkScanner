def sanitize_name(name):
    return name.replace(".", "_").replace("/", "_").replace(":", "_").replace("\\", "_")