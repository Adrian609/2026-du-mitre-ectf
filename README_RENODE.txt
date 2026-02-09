How to compile for Renode?

In 2026-ectf-insecure-renode/firmware/Makefile, there is a field called ON_BOARD. 
Ensure it is equal to 0. Then follow the same steps you use to compile the reference 
design (Docker and all that). 

At the end, you should have 2026-ectf-insecure-renode/build/hsm.bin.

-----------

How to install Renode?

See https://github.com/renode/renode. I just downloaded renode_1.16.0_arm64.deb from 
https://github.com/renode/renode/releases and ran

$ sudo apt install renode_1.16.0_arm64.deb


-----------

How to run in Renode?

In a terminal, go to 2026-ectf-insecure-renode/renode/. Type 

$ renode run_hsm.resc

Observe the outputs. You can interact with the renode simulation from host computer using 
/tmp/hsm0_uart0 (in uvx ectf commands).

-----------

How to start another simulation?

$ renode run_hsm2.resc

Here the ports are /tmp/hsm0_uart0 and /tmp/hsm1_uart0 for the two boards. One of the pop-up
windows (one whose title ends with ...uart1) is the board to board traffic.

This simulation uses the same firmware image for both boards. As such, their pins and keys
will also be same. Ideally, you would clone the entire folder, build separateley, and then
make the simulation use two different images. We can test that out later!!

-----------

How to deploy on board?

In the Makefile, change ON_BOARD to 1. The created 2026-ectf-insecure-renode/build/hsm.bin is 
ready to be put on board. Ensure the firmware runs on board as well and actually produces the 
same outputs you see in the simulation.


IMPORTANT!!!

In the final submission, we will do more cleanup (like removing TODOs or debug statements). 

