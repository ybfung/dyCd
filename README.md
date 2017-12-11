# Abstract
Today, with the ubiquitous of computing devices, such as mobile phones, tablets, laptops and the traditional desktop computers, the eagerness of software applications running on those devices are exponentially increase. Without properly educated and understanding of the software being installed, users have exposed themselves the numerous risks for cyber threats such as viruses, malwares, keylogger, trojan, ransomwares and so on. However, those threats are nothing new but exists since the born of the computer digital world. Those old wine in a new bottle (same good old tricks with new labels) attacks are always failed to be detected by most of the anti-viruse tools due to the limitations of signature based detection methods. In order to defeat these good old tricks so called zero-day attack, we need a generic way to understand the semantic of software binaries. This paper introduces a new method to dynamically compare two binary functions for the semantic differences. This smenatic comparison can be used as a virus detection framework that it can effectively increase the detection rate for a target softwore from a pool of known harmful behaviors.   

# Introduction
Computer software binary is a set of machine instructions that is non-human readable sequence of ones and zeros byte stream to instruct what operations a digital device would perform. Without a proper program such as disassembler, it is almost impossible for us to interpret what the binary would do. Same situation applies when try to compare the content of two pieces of binary functions for which they may be compiled with different compilers, built for different machine architectures, or coded with different implementations. 

In cyber security, the ability to compare or to understand the context of a piece of software is essential because most of the computer viruses, malwares or malicious computer binary fragments always conceal itself from legit binaries, especially for a zero-day attack. However, based on the difficulities memtioned, there is by far no esay or an effective way to search for a known hidden harmful binary fragment from a legit binary. Although there have been many researches, such as N-Gram, data mining, CFG, none of them can accurately provides semantical information of a binary, which can be measured for comparison due to either it's too slow or high false positive rate. To this end, *dyCd* is a dynamic binary clone detection tool, which based on the symbolic execution to effectively detect a sementic clone for the given two binary functions.




