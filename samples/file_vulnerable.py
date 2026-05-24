def read_config():
    f = open("config.txt", "r")
    data = f.read()
    f.close()
    return data

def write_log(message):
    f = open("log.txt", "w")
    f.write(message)
    f.close()
