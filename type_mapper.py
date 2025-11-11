MAGIC_TO_EXT = {
    'png': '.png',
    'jpeg': '.jpg',
    'gif': '.gif',
    'pdf': '.pdf',
    'zip': '.zip',
    'rar': '.rar',
    'gzip': '.gz',
    'bzip2': '.bz2',
    'elf': '.elf',
    'text': '.txt',
    'binary': '.bin',
    'empty': '.bin'
}

def get_extension(magic_name: str):
    return MAGIC_TO_EXT.get(magic_name.lower(), '.bin')

