class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def green(line, number=""):
    lend = '\33[0m'
    lgreen = '\033[92m'
    print(lgreen + line + lend + str(number))


def red(line, number=""):
    lend = '\33[0m'
    lred = '\033[91m'
    print(lred + line + lend + str(number))

def cyan(line, number=""):
    lend = '\33[0m'
    lcyan = '\033[96m'
    print(lcyan + line + lend + str(number))