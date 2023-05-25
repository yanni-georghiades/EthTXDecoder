# EthTXDecoder

## **Theoretical Portion:**

1. Given transaction and logs, how could we determine whether the transaction invoked involved NFT transfer? (i.e ERC721 compliant contract) 

The transaction payload should begin with the message id of a safeTransferFrom or transferFrom method that implements the ERC721 interface. E.g., the method id for transferFrom is 0x23b872dd.

In addition, in order to confirm that a the transfer was successful, the contract should emit the Transfer event in the logs. 

However, it seems like it may be possible for an NFT transfer to occur in certain situations without invoking the standard ERC721 transfer methods. The owner of a contract, for example, may be able to manually modify ownership of an NFT if they design the contract to allow this. Need to look into this further.

2. System Design: Think through design details of a decoding system that decodes transactions at scale. (assume you have access to a cloud provider like AWS or GCP)
    1. It should have a batch-processing mode that decodes entire history through genesis
    2. It can should also have a streaming mode that decodes latest transactions in near-real-time.
    3. In your exercise you may have had to pick a contract and find its ABI. How could this system handle arbitrary contracts (or at least popular ones)?


### Design Goals: 
- High degree of parallelization. Transactions can be decoded independently of one another.
- Streaming mode should be able to decode transactions faster than rate at which they are processed by the system (for Ethereum this is ~30 TPS)
- Decoded transaction data should be stored in an efficient database for accessibility
- ABIs should be found when available and cached
- 

### Design Decisions:
- Which transactions do we need to be able to access at any time? Are we storage-constrained? Are there subsets of transaction data that can be discarded? E.g., failed transactions, old transactions, certain types of transactions. 
- What percentage of transactions do we need to be able to decode? Is it ok to only decode the transactions for which the ABI is readily available? Is it worth the effort to manually search for ABIs on github or other websites? Is it worth the effort to attempt to reverse engineer the bytecode in any way? How many examples of a transaction execution do we need to see before we attempt it? 
- How quickly does the initial batch processing need to be executed?  
- How much do we trust the block explorer/data provider we select? Do we need to run our own ETH node to guarantee high data fidelity? Is running an ETH node cheaper than paying for infura or other API access? 
- 














