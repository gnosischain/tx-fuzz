package main

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

var (
	lastBaseFee   *big.Int
	lastGasUsage  uint64
	fuzzerSenders map[common.Address]struct{}
)

func watchBlocks() {
	fuzzerSenders = make(map[common.Address]struct{})

	for _, addr := range addrs {
		// initialize senders to watch for
		fuzzerSenders[addr] = struct{}{}
	}

	backend, _ := getRealBackend()
	client := ethclient.NewClient(backend)
	chainid, err := client.ChainID(context.Background())
	if err != nil {
		panic(err)
	}
	headCh := make(chan *types.Header)
	headSubscription, err := client.SubscribeNewHead(context.Background(), headCh)
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			select {
			case err := <-headSubscription.Err():
				panic(err)
			case header := <-headCh:
				block, err := client.BlockByHash(context.Background(), header.Hash())
				if err != nil {
					panic(err)
				}
				processNewBlock(chainid, block)
			}
		}
	}()
}

func processNewBlock(chainid *big.Int, block *types.Block) {
	lastBaseFee = block.BaseFee()
	lastGasUsage = 100 * block.GasUsed() / block.GasLimit()

	txs := block.Transactions()
	signer := types.NewLondonSigner(chainid)
	go func() {
		txCount := 0
		for _, tx := range txs {
			if sender, err := types.Sender(signer, tx); err != nil {
				panic(err)
			} else if _, isFuzzerSender := fuzzerSenders[sender]; isFuzzerSender {
				txCount++
				if verbose {
					fmt.Printf("Included tx{sender: %v, nonce: %v} in block %v\n", sender.Hex(), tx.Nonce(), block.NumberU64())
				}
			}
		}
		fmt.Printf("Included %v transaction in block %v - block gas usage was %v percent\n", txCount, block.NumberU64(), 100*block.GasUsed()/block.GasLimit())
	}()
}
