Deep dive in code

Tornado trees- merkle trees are computed offchain and then prove validity on chain 

The length of the subtrees should be specified before in order to initialize the tree at the start. Moreover, a snark proof for example always requires fixed-sized loops similar to fixed-sized chunks.

Each insertion cost 300k gwei for checking the snark proof.

The 

Contracts will check the old root and new root, both as public input.

When the subtree is not complete, the data is stored on a server which accumulates the transaction. Note that the server or the protocol needs to be open source for the users to communicate their data. Moreover, the snark prover needs to be open-sourced as a result of a trusted setup ceremony.

In case of Tornado cash, each insertion is committed onchain and the corresponding event is emitted. So to accumulate the chunk one simply needs to wait to combine these into chunks.

When the merkle tree is full, the next transaction will fail so we would need to deploy another Tree contract. However, in tornado cash the tree is so big that it would never fill up.



circuits/BatchTreeUpdate.circom

Using circom v1 so have to specify private inputs. From circom v2, all inputs are assumed private unless specified in the main.
```circom=

// Inserts a leaf batch into a tree
// Checks that tree previously contained zero leaves in the same position
// Hashes leaves with Poseidon hash
// `batchLevels` should be less than `levels`
template BatchTreeUpdate(levels, batchLevels, zeroBatchLeaf) {
  var height = levels - batchLevels;
  var nLeaves = 1 << batchLevels;
  signal input argsHash;
  signal private input oldRoot;
  signal private input newRoot;
  signal private input pathIndices;
  signal private input pathElements[height];
  signal private input hashes[nLeaves];
  signal private input instances[nLeaves];
  signal private input blocks[nLeaves];

  // Check that hash of arguments is correct
  // We compress arguments into a single hash to considerably reduce gas usage on chain
  component argsHasher = TreeUpdateArgsHasher(nLeaves);
  argsHasher.oldRoot <== oldRoot;
  argsHasher.newRoot <== newRoot;
  argsHasher.pathIndices <== pathIndices;
  for(var i = 0; i < nLeaves; i++) {
    argsHasher.hashes[i] <== hashes[i];
    argsHasher.instances[i] <== instances[i];
    argsHasher.blocks[i] <== blocks[i];
  }
  argsHash === argsHasher.out;
```

To verify the snarks, each public input is used to do one EC addition and multiplication which costs around 6000 gwei. 

Verifier2.sol
```js=
    function verifyProof(
        bytes memory proof,
        uint256[7] memory input
    ) public view returns (bool) {
        uint256[8] memory p = abi.decode(proof, (uint256[8]));
        for (uint8 i = 0; i < p.length; i++) {
            // Make sure that each element in the proof is less than the prime q
            require(p[i] < PRIME_Q, "verifier-proof-element-gte-prime-q");
        }
        Pairing.G1Point memory proofA = Pairing.G1Point(p[0], p[1]);
        Pairing.G2Point memory proofB = Pairing.G2Point([p[2], p[3]], [p[4], p[5]]);
        Pairing.G1Point memory proofC = Pairing.G1Point(p[6], p[7]);

        VerifyingKey memory vk = verifyingKey();
        // Compute the linear combination vkX
        Pairing.G1Point memory vkX = vk.IC[0];
        for (uint256 i = 0; i < input.length; i++) {
            // Make sure that every input is less than the snark scalar field
            require(input[i] < SNARK_SCALAR_FIELD, "verifier-input-gte-snark-scalar-field");
            vkX = Pairing.plus(vkX, Pairing.scalarMul(vk.IC[i + 1], input[i]));
        }
```

However, to optimize gas prices for larger subtrees, all inputs are hashed and given as a public input to the snark in the TornadoTree contract. We do have to pay th price for increased constraints in the snark. 

Additionally we have to upload arguments into the calldata in solidity and compute sha hash which comes with further costs.

Note that sha-256 has been used as the hash function. This is computed both on-chain and in the snark prover. Implementing a snark-friendly hash function like poseidon would increase the computation on-chain making it more costly overall.

Tornado.sol checks that elements are pushed into the subtrees sequentially. We choose not to emit events as it is 10x costly than calldata. However, any ethereum node can call the transaction that fetch method "UpdateDepositTree", then fetch the transaction data from block and decode the calldata the arguments supplied by the user. 

```js=
  /// @dev Insert a full batch of queued deposits into a merkle tree
  /// @param _proof A snark proof that elements were inserted correctly
  /// @param _argsHash A hash of snark inputs
  /// @param _currentRoot Current merkle tree root
  /// @param _newRoot Updated merkle tree root
  /// @param _pathIndices Merkle path to inserted batch
  /// @param _events A batch of inserted events (leaves)
  function updateDepositTree(
    bytes calldata _proof,
    bytes32 _argsHash,
    bytes32 _currentRoot,
    bytes32 _newRoot,
    uint32 _pathIndices,
    TreeLeaf[CHUNK_SIZE] calldata _events
  ) public {
    uint256 offset = lastProcessedDepositLeaf;
    require(_currentRoot == depositRoot, "Proposed deposit root is invalid");
    require(_pathIndices == offset >> CHUNK_TREE_HEIGHT, "Incorrect deposit insert index");

    bytes memory data = new bytes(BYTES_SIZE);
    assembly {
      mstore(add(data, 0x44), _pathIndices)
      mstore(add(data, 0x40), _newRoot)
      mstore(add(data, 0x20), _currentRoot)
    }
    for (uint256 i = 0; i < CHUNK_SIZE; i++) {
      (bytes32 hash, address instance, uint32 blockNumber) = (_events[i].hash, _events[i].instance, _events[i].block);
      bytes32 leafHash = keccak256(abi.encode(instance, hash, blockNumber));
      bytes32 deposit = offset + i >= depositsV1Length ? deposits[offset + i] : tornadoTreesV1.deposits(offset + i);
      require(leafHash == deposit, "Incorrect deposit");
      assembly {
        let itemOffset := add(data, mul(ITEM_SIZE, i))
        mstore(add(itemOffset, 0x7c), blockNumber)
        mstore(add(itemOffset, 0x78), instance)
        mstore(add(itemOffset, 0x64), hash)
      }
      if (offset + i >= depositsV1Length) {
        delete deposits[offset + i];
      } else {
        emit DepositData(instance, hash, blockNumber, offset + i);
      }
    }

    uint256 argsHash = uint256(sha256(data)) % SNARK_FIELD;
    require(argsHash == uint256(_argsHash), "Invalid args hash");
    require(treeUpdateVerifier.verifyProof(_proof, [argsHash]), "Invalid deposit tree update proof");

    previousDepositRoot = _currentRoot;
    depositRoot = _newRoot;
    lastProcessedDepositLeaf = offset + CHUNK_SIZE;
  }
```

