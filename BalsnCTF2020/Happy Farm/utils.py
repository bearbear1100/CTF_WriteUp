import os

PER_LENGTH = 256

flag = b"BALSN{This_is_not_the_real_flag.Do_not_try_to_upload_it}"


banner1 = """
Onion one:
"""

banner2 = """
Onion two:
"""

banner3 = """
Last Onion!
No seed this time!
"""


class Drawer:
    SEED = None
    ONION = None
    EATEN_ONION = None

    def __init__(self):
        if Drawer.SEED is None:
            with open("seed.txt") as f:
                Drawer.SEED = f.read().strip("\n").split("\n")
        if Drawer.ONION is None:
            with open("onion.txt") as f:
                Drawer.ONION = f.read().strip("\n").split("\n")
        if Drawer.EATEN_ONION is None:
            with open("eaten_onion.txt") as f:
                Drawer.EATEN_ONION = f.read().strip("\n").split("\n")

    def draw(self, name, target):
        target = target.hex()
        if len(target) % PER_LENGTH != 0:
            target += "x" * (PER_LENGTH - (len(target) % PER_LENGTH))

        repeat = len(target) // PER_LENGTH
        cnt = 0
        to_draw = ""
        banner = eval("Drawer." + name)
        for line in banner:
            for _ in range(repeat):
                for c in line:
                    if c == " ":
                        to_draw += " "
                    elif c == "x":
                        to_draw += " "
                        cnt += 1
                    else:
                        to_draw += target[cnt]
                        cnt += 1
            to_draw += "\n"

        print(to_draw)

    def draw_seed(self, target):
        self.draw("SEED", target)

    def draw_onion(self, target):
        self.draw("ONION", target)

    def draw_eaten_onion(self, target):
        self.draw("EATEN_ONION", target)
