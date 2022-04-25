pragma solidity ^0.8.11;


contract Test {
    constructor() {}

    function free_looping(uint v) public returns(uint)
    {
        uint val = 0;
        for (uint i=0;i<v;i++) {
            if (val > i) {
                val = i;
            } else {
                val = 3;
            }
        }
        return val;
    }
}

