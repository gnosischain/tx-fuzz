package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strconv"

	txfuzz "github.com/MariusVanDerWijden/tx-fuzz"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

var (
	keys  []*ecdsa.PrivateKey
	addrs []common.Address
)

func initAccounts(mnemonic string, startIdx, endIdx int) {
	keys = make([]*ecdsa.PrivateKey, 0, endIdx-startIdx)
	addrs = make([]common.Address, 0, endIdx-startIdx)

	masterKey, err := bip32.NewMasterKey(bip39.NewSeed(mnemonic, ""))
	if err != nil {
		panic(err)
	}

	for idx := startIdx; idx < endIdx; idx++ {
		path, err := accounts.ParseDerivationPath(strconv.Itoa(idx))
		if err != nil {
			panic(err)
		}
		key := masterKey
		for _, edge := range path {
			key, err = key.NewChildKey(edge)
			if err != nil {
				panic(err)
			}
		}

		sk, err := crypto.ToECDSA(key.Key)
		if err != nil {
			panic(err)
		}
		addr := crypto.PubkeyToAddress(sk.PublicKey)

		keys = append(keys, sk)
		addrs = append(addrs, addr)

		fmt.Printf("Generated account derived at %v to send txs from: %v\n", idx, addr.Hex())
	}
}

func airdrop(targetValue *big.Int) bool {
	client, sk := getRealBackend()
	backend := ethclient.NewClient(client)
	sender := common.HexToAddress(txfuzz.ADDR)
	var tx *types.Transaction
	chainid, err := backend.ChainID(context.Background())
	if err != nil {
		fmt.Printf("could not airdrop: %v\n", err)
		return false
	}

	// Get nonce
	fmt.Printf("getting nonce\n")
	nonce, err := backend.PendingNonceAt(context.Background(), sender)
	if err != nil {
		fmt.Printf("could not get nonce: %v\n", err)
		return false
	}
	fmt.Printf("Nonce: %v\n", nonce)
	fmt.Printf("getting gas price\n")
	gp, _ := backend.SuggestGasPrice(context.Background())
	fmt.Printf("Gas Price: %v\n", gp)

	fmt.Printf("Target value for airdrop %v wei\n", targetValue)
	for _, to := range addrs {
		balance, err := backend.PendingBalanceAt(context.Background(), to)
		if err != nil {
			fmt.Printf("could not airdrop: %v\n", err)
			return false
		}
		value := new(big.Int).Sub(targetValue, balance)
		if value.Cmp(big.NewInt(0)) <= 0 {
			fmt.Printf("Addr %v already has %v wei\n", to.Hex(), balance)
			continue
		}
		fmt.Printf("Addr %v will be airdropped %v wei\n", to.Hex(), value)

		// nonce, err := backend.PendingNonceAt(context.Background(), sender)
		// if err != nil {
		// 	fmt.Printf("could not airdrop: %v\n", err)
		// 	return false
		// }
		// gp, _ := backend.SuggestGasPrice(context.Background())
		// tx2 := types.NewTransaction(nonce, to, value, 21000, gp.Mul(gp.Add(gp, common.Big1), common.Big2), nil)
		tx2 := types.NewTransaction(nonce, to, value, 21000, big.NewInt(0), nil)
		nonce++
		signedTx, err := types.SignTx(tx2, types.LatestSignerForChainID(chainid), sk)
		if err != nil {
			fmt.Printf("could not airdrop: %v\n", err)
			return false
		}
		if err := backend.SendTransaction(context.Background(), signedTx); err != nil {
			fmt.Printf("could not airdrop: %v\n", err)
			return false
		}
		tx = signedTx
	}
	if tx == nil {
		fmt.Printf("could not airdrop")
		return false
	}
	// Wait for the last transaction to be mined
	bind.WaitMined(context.Background(), backend, tx)
	fmt.Printf("airdrop succesful\n")
	return true
}

func withdraw(gasPrice *big.Int) bool {
	client, _ := getRealBackend()
	backend := ethclient.NewClient(client)
	recipient := common.HexToAddress(txfuzz.ADDR)
	var tx *types.Transaction
	chainid, err := backend.ChainID(context.Background())
	if err != nil {
		fmt.Printf("could not withdraw: %v\n", err)
		return false
	}

	fmt.Printf("Gas Price: %v\n", gasPrice)

	for idx, from := range addrs {
		balance, err := backend.PendingBalanceAt(context.Background(), from)
		if err != nil {
			fmt.Printf("could not withdraw: %v\n", err)
			return false
		}

		fmt.Printf("Addr %v\n", from.Hex())
		fmt.Printf("Current Balance %v\n", balance)
		if balance.Cmp(big.NewInt(0)) <= 0 {
			fmt.Printf("Addr %v already has %v wei\n", from.Hex(), balance)
			continue
		}

		nonce, err := backend.PendingNonceAt(context.Background(), from)
		if err != nil {
			fmt.Printf("could not get nonce: %v\n", err)
			return false
		}
		value := new(big.Int).Sub(balance, big.NewInt(21000))
		fmt.Printf("To withdraw:   %v\n", value)
		fmt.Printf("Nonce: %v\n", nonce)

		tx2 := types.NewTransaction(nonce, recipient, value, 21000, gasPrice, nil)
		signedTx, err := types.SignTx(tx2, types.LatestSignerForChainID(chainid), keys[idx])
		if err != nil {
			fmt.Printf("could not withdraw: %v\n", err)
			return false
		}
		if err := backend.SendTransaction(context.Background(), signedTx); err != nil {
			fmt.Printf("could not withdraw: %v\n", err)
			return false
		}
		tx = signedTx
	}
	if tx == nil {
		fmt.Printf("could not withdraw")
		return false
	}
	// Wait for the last transaction to be mined
	bind.WaitMined(context.Background(), backend, tx)
	fmt.Printf("withdraw succesful\n")
	return true
}
