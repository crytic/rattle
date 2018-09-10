pragma solidity ^0.4.24;
 
contract LogicContract {
  uint public a;
 
  function set(uint val) public {
    a = val;
  }
}
 
contract ProxyContract {
  address public contract_pointer;
  uint public a;
 
  constructor() public {
    contract_pointer = address(new LogicContract());
  }
 
  function set(uint val) public {
    // Note: the return value of delegatecall should be checked
    contract_pointer.delegatecall(bytes4(keccak256("set(uint256)")), val);
  }

  function upgrade(address new_contract) public {
      contract_pointer = new_contract;
  }

  function() {
    contract_pointer.delegatecall(bytes4(keccak256("set(uint256)")), 0);
  }
}
