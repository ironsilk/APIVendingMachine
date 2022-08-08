import logging


# Logger settings
def setup_logger(name, log_file=None, level=logging.INFO):
    """Function to setup as many loggers as you want"""
    formatter = logging.Formatter('[%(asctime)s] {%(filename)s:%(lineno)d} [%(name)s] [%(levelname)s] --> %(message)s')
    out_handler = logging.StreamHandler()
    out_handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(out_handler)
    if log_file:
        handler = logging.FileHandler(log_file, encoding='utf8')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


logger = setup_logger("APIVendingMachine")


def calculate_change(change):
    """
    Function that will return an array of
    5,10,20,50 or 100 coins as change.
    """
    # TODO can replace here with env variable for the
    #  coin types in order to change easier.

    coins = []
    for value in [100, 50, 20, 10, 5]:
        coins.extend([value] * int(change / value))
        change = change % value
    return coins


if __name__ == '__main__':
    change = 275
    print(calculate_change(change))
