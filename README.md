# SwitchML – Programming Assignment Part B (CS5229, 2024)

This repository contains my personal implementation of **Part B** of the programming assignment from the course **CS5229: Parallel and Distributed Algorithms** offered at the **National University of Singapore (NUS)**.

**Original assignment link**:  
[https://github.com/NUS-CIR/cs5229-2024-pa2/tree/main/part_b/switchml](https://github.com/NUS-CIR/cs5229-2024-pa2/tree/main/part_b/switchml)

**Disclaimer**:  
The original project and its framework were developed by the course instructors at NUS. I completed this assignment independently for educational purposes. I do not claim ownership of the base code or the assignment design. This repository contains only my own implementation and understanding of the tasks defined in Part B.

---

## What is SwitchML?

**SwitchML** is a system designed to accelerate distributed machine learning training by leveraging programmable network switches. Instead of aggregating gradients at a central parameter server (which can be a bottleneck), SwitchML offloads simple aggregation operations (like element-wise addition) to the data plane of the network — typically using **P4-enabled** programmable switches.

This enables faster gradient synchronization across multiple worker nodes, reducing the communication overhead during training of large-scale models in data-parallel ML setups.

---

## What’s in This Repository?

This repository focuses specifically on **Part B** of the assignment, which involves:

- Understanding and modifying the **SwitchML architecture**.
- Implementing custom logic for **gradient fragmentation and reassembly** across switches.
- Extending and debugging **packet-handling code** for worker-switch interaction.
- Testing the functionality using the provided **emulated environment**.

The implementation required working with:
- **P4** for switch programming.
- **Python** scripts for simulating workers and managing training.
- **Mininet** to emulate a network of workers and switches.

---

## How to Run

To test or experiment with this implementation, follow the setup instructions provided in the original repository:
[cs5229-2024-pa2 – SwitchML Part B](https://github.com/NUS-CIR/cs5229-2024-pa2/tree/main/part_b/switchml)

---

## My Contribution

I implemented and debugged the key functionalities as instructed in the original assignment, including:

- Ensuring correct gradient aggregation behavior.
- Debugging P4 logic to handle concurrent worker updates.
- Managing buffer indexing and synchronization between workers and switch.
- Testing the pipeline using the emulated topology.

---

## References

- [CS5229 Course Page](https://nus-cir.github.io/cs5229-2024/)
- [Original GitHub Repository for PA2](https://github.com/NUS-CIR/cs5229-2024-pa2)
