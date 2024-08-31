+++
title = "Bypassing isContract check in Smart contracts"
date = 2024-08-31T11:36:33+08:00
draft = false
[taxonomies]
tags=["solidity","smart contracts"]
[extra]
toc=true
+++

In the world of smart contract development, ensuring that only certain types of accounts can interact with your contract is crucial for maintaining security. One of the most common techniques used for this purpose is the `isContract` check. This check is often implemented to distinguish between externally owned accounts (EOAs) and other smart contracts, allowing developers to restrict or permit specific interactions.

In this blog post, we will dive into the `isContract` check, explain how it works, and explore how it can be bypassed by an attacker. Understanding these mechanics is essential for any Solidity developer who wants to secure their smart contracts against common vulnerabilities.

Let's start by examining the `isContract` check itself, which is typically implemented as follows:
```js
function isContract(address account) public view returns (bool) {
    uint size;
    assembly {
        size := extcodesize(account)
    }
    return size > 0;
}
```
First line defines a public function named isContract that takes an address as input and returns a boolean value. The view keyword indicates that this function does not modify the contract's state, only reads from it. A local variable size is declared to store the size of the code at the given address. This will be used to determine if the address belongs to a contThisract or an EOA.

Assembly block of code uses Solidity's inline assembly to access lower-level operations. The `extcodesize` opcode is called, which retrieves the size of the code stored at the specified address. The result is stored in the size variable. If the address is an EOA, extcodesize will return 0, as EOAs have no associated code. If the address is a contract, extcodesize will return a value greater than 0.

## Check in action

Now that we've covered how the `isContract` check works, let's see it in action within the King of Ether game. The King of Ether game is a well-known example among Solidity developers. It is simple to implement but also serves as an excellent demonstration of a Denial of Service (DOS) attack. The game revolves around a single function call to claim the throne, where the caller becomes the new king if they send more Ether than the current king. The Ether sent by the previous king is then returned to them.

If someone were to call the `claimThrone` function from a smart contract that does not implement a `fallback` function, they would successfully take the throne. However, any subsequent attempts by others to claim the throne with a higher bid would fail. This failure occurs because the Ether return transaction to the attacking contract (the current king) would revert due to the missing `fallback` function. As a result, the contract becomes permanently locked, preventing anyone else from becoming the king.

To address this vulnerability, we expanded the King of Ether game by implementing a check to determine whether the caller is a smart contract. It might seem at first glance that this issue could be resolved by checking the size of the code at the caller's address using the `isContract` check.

Here’s the implementation of the `claimThrone` function, now with the `isContract` check in place:
```js
pragma solidity ^0.8.10;

contract KingOfEther {
    address public king;
    uint public balance;

    function isContract(address account) public view returns (bool) {
        uint size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    function claimThrone() external payable {
        require(msg.value > balance, "Need to pay more to become the king");
        require(!isContract(msg.sender), "No contract allowed");

        (bool sent, ) = king.call{value: balance}("");
        require(sent, "Failed to send Ether");

        balance = msg.value;
        king = msg.sender;
    }
}
```

In this expanded version of the game, we introduced the isContract check to prevent smart contracts from claiming the throne. However, as we will explore in the next section, even this enhanced protection can be bypassed.

## Bypassing the check

An attacker looking to bypass the `isContract` check can do so by leveraging a specific property of how Ethereum smart contracts are deployed. The key to this attack lies in understanding that the code within a contract's constructor is executed before the contract is fully deployed. This means that during the execution of the constructor, the contract's code size is still zero, making the `extcodesize` check ineffective.

The attacker should move the call to the `claimThrone` function into the constructor of a malicious contract. Since the contract's code is not yet deployed at the time the constructor runs, the `extcodesize` function returns 0. This tricks the `isContract` check into treating the attacker’s contract as if it were an externally owned account (EOA), allowing the contract to claim the throne.


Here’s an example of such a malicious contract:
```js
contract exploitKing {
    KingOfEtherInterface kingOfEtherAddress;

    constructor(KingOfEtherInterface _kingOfEther) payable {
        kingOfEtherAddress = KingOfEtherInterface(_kingOfEther);
        kingOfEtherAddress.claimThrone{value: msg.value}();
    }
}
```
This attack effectively bypasses the security measure implemented by the isContract check, highlighting a critical vulnerability in smart contract development. Understanding this attack is crucial for developers to implement more robust security measures in their contracts.

## Effective methods to determine if the caller is a contract

Given the limitations of the `isContract` check, particularly its vulnerability to constructor-based exploits, developers must consider alternative strategies to more accurately determine if the caller is a contract. Here are some more robust approaches:

### Time-Based or Multi-Transaction Validation

One approach is to delay the critical operations that should not be executed by contracts until after the deployment is complete. For instance, you could require the caller to perform a multi-step process, where the final step occurs after the contract's deployment. In this example, `claimThrone` function would be split in two, first `initClaimThrone` which locally registers request for claiming at a specific and after that second `claimThrone` function which can be executed after the current block is incemented.

### Using the tx.origin for Certain Checks

In some cases, you might consider using the tx.origin variable, which returns the original sender of the transaction. While generally discouraged for authorization purposes due to its susceptibility to phishing and other attacks, tx.origin can be useful in specific contexts where you want to ensure that the transaction originates from an EOA.

Example of check:
```js
require(tx.origin == msg.sender, "Caller must be EOA");
```