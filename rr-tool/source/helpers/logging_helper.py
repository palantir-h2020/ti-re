import logging


def format_logger(logger):
    consoleHandler = logging.StreamHandler()
    consoleHandler.setLevel(logging.DEBUG)
    # noinspection SpellCheckingInspection
    formatter = logging.Formatter('%(asctime)s [%(name)s] %(levelname)s %(message)s')
    consoleHandler.setFormatter(formatter)
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.addHandler(consoleHandler)
    logger.propagate = False
    pass


def get_logger(name: str) -> logging.Logger:
    if name == 'rr-tool':
        return root_logger
    else:
        child_logger = root_logger.getChild(name)
        format_logger(child_logger)
        return child_logger
    pass


def get_child_logger(root: str, name: str) -> logging.Logger:
    if name == 'rr-tool':
        return root_logger
    else:
        child_logger = logging.getLogger(root).getChild(name)
        format_logger(child_logger)
        return child_logger
    pass


root_logger = logging.getLogger('rr-tool')
format_logger(root_logger)
