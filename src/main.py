from uav import uav
import ground

def main():
    print("Hello from 2027-ectf-crypto-lab!")
    my_uav = uav.UAV

    ground.send()
    # instantiate uav class
    # instantiate ground class
    # instantiate attacker class
    # start uav
    # use ground class to send messages to uav
    # assert versions on state of uav

if __name__ == "__main__":
    main()


# pytest

# phase 1

# without hash
def ground_update() -> bool:
    # ground.send(payload with hash)
    return False 
def attacker_update() -> bool:
    # ground.send(payload with hash)
    return False 

def ground_update_with_hash() -> bool:
    # ground.send(payload with hash)
    return False 

def ground_update_with_signature() -> bool:
    # ground.send(payload with hash)

    return False 

def attacker_update_with_hash() -> bool:
    return False 


def TestPhase1():
    assert(not ground_update())
    assert(ground_update_with_hash())
    assert(attacker_update_with_hash())

def TestPhase2():
    assert(not ground_update())
    assert(not ground_update_with_hash())
    assert(ground_update_with_signature())
    assert(not attacker_update_with_hash())

def TestPhase3():
    ???
