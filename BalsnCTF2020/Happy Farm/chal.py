#!/usr/bin/env python3.8
import os
import time

from Cryptodome.Cipher import AES
from Cryptodome.Util.number import *

from fertilizers import Fertilizer1, Fertilizer2, Fertilizer3
from utils import Drawer, banner1, banner2, banner3, flag

TARGET_LAYER = 9000
TARGET_BLOCKS = 16
BLOCK_SIZE = 16



def level1():
    print(banner1)
    my_seed = os.urandom(BLOCK_SIZE * TARGET_BLOCKS)
    print(f"My seed:")
    drawer.draw_seed(my_seed)
    my_start_date = os.urandom(BLOCK_SIZE)
    print(f"My start date: {my_start_date.hex()}")

    for _ in range(2):
        ## read request pair (start_date, seed, layer)
        start_date = bytes.fromhex(input("start date: "))
        if len(start_date) != BLOCK_SIZE:
            raise Exception
        seed = bytes.fromhex(input("seed: "))
        if len(seed) % BLOCK_SIZE != 0 or my_seed in seed:
            raise Exception
        layer = int(input("layer: "))
        if layer < 0 or layer >= TARGET_LAYER:
            raise Exception

        # encrypt for "layer" times and then send back the result
        fertilizer = Fertilizer1(start_date)
        onion = fertilizer.grow(seed, layer)
        print(f"Your onion")
        drawer.draw_onion(onion)

    guessed_onion = bytes.fromhex(input("How would my onion looks like? "))
    fertilizer = Fertilizer1(my_start_date)
    onion = fertilizer.grow(my_seed, TARGET_LAYER)
    if guessed_onion == onion:
        print(f"What a prophet!")
        return True
    else:
        print(f"...?")
        return False


def level2():
    print(banner2)

    fertilizer = Fertilizer2()
    my_seed = fertilizer.seed

    while True :
        fertilizer =  Fertilizer2()
        my_seed = fertilizer.seed
        if fertilizer.grow(my_seed, TARGET_LAYER).hex()[173] == '0' :
            break
    print(f"My seed is")
    drawer.draw_seed(my_seed)
    print(f"You should use my seed first!")

    ## read request (layer)
    layer = int(input("layer: "))
    if layer < 0 or layer >= TARGET_LAYER:
        raise Exception

    highest_layer = 8998
    if layer >= 2:
        print(f"The layer you request is too high!")
        print(f"You cannot request layer higher than this!")
        highest_layer = layer

    ## encrypt for "layer" times and then send back the result
    onion = fertilizer.grow(my_seed, layer)
    print(f"your onion")
    drawer.draw_onion(onion)

    print(f"You can now use your seed")
    seed = bytes.fromhex(input("seed: "))
    layer = int(input("layer: "))
    if layer < 0 or layer >= TARGET_LAYER or layer > highest_layer:
        raise Exception

    onion = fertilizer.grow(seed, layer)
    time.sleep(1)
    print(
        f"Oops! It seems that some naughty rats sneak a taste on your onion while I'm napping!"
    )
    print(f"Here you go")
    drawer.draw_eaten_onion(onion)

    guessed_onion = bytes.fromhex(input("How would my onion looks like? "))
    onion = fertilizer.grow(my_seed, TARGET_LAYER)
    if guessed_onion == onion:
        print(f"What a prophet!")
        return True
    else:
        print(f"...?")
        print(onion)
        return False


def level3():
    print(banner3)

    seed_length = 15 * TARGET_BLOCKS
    my_seed = os.urandom(seed_length)

    for _ in range(4):
        fertilizer = Fertilizer3()

        ## read request (layer)
        layer = int(input("layer: "))
        if layer < 0 or layer >= TARGET_LAYER:
            raise Exception

        ## encrypt for "layer" times and then send back the result
        onion = fertilizer.grow(my_seed, layer)
        print(f"your onion")
        drawer.draw_onion(onion)

    print(f"To pass the last challenge, your power should be over 9000!!!")
    guessed_onion = bytes.fromhex(input("How would my onion looks like? "))
    fertilizer = Fertilizer3()
    try:
        onion = fertilizer.doctor_Balsn(my_seed, TARGET_LAYER ** 3 % 192)
    except NotImplementedError:
        onion = fertilizer.grow(my_seed, TARGET_LAYER ** 3 % 192)

    if guessed_onion == onion:
        print(f"What a prophet!")
        return True
    else:
        print(f"...?")
        return False

    return True


def main():
    if not level1():
        return

    if not level2():
        return

    if not level3():
        return

    print(flag)


drawer = Drawer()
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("Something went wrong...")
