package main

import (
	"context"
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
	keys  []string
	addrs []string
)

func initAccounts(mnemonic string, startIdx, endIdx int) {
	keys = make([]string, 0, endIdx-startIdx)
	addrs = make([]string, 0, endIdx-startIdx)

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

		addrHex := crypto.PubkeyToAddress(sk.PublicKey).Hex()
		skHex := "0x" + common.Bytes2Hex(crypto.FromECDSA(sk))
		// Sanity check marshalling
		if _, err := crypto.ToECDSA(crypto.FromECDSA(sk)); err != nil {
			panic(err)
		}
		keys = append(keys, skHex)
		addrs = append(addrs, addrHex)

        fmt.Printf("Generated account derived at %v to send txs from: %v\n", idx, addrHex)
	}
}

func airdrop(value *big.Int) bool {
	client, sk, _ := getRealBackend()
	backend := ethclient.NewClient(client)
	sender := common.HexToAddress(txfuzz.ADDR)
	var tx *types.Transaction
	chainid, err := backend.ChainID(context.Background())
	if err != nil {
		fmt.Printf("could not airdrop: %v\n", err)
		return false
	}
	for _, addr := range addrs {
		nonce, err := backend.PendingNonceAt(context.Background(), sender)
		if err != nil {
			fmt.Printf("could not airdrop: %v\n", err)
			return false
		}
		to := common.HexToAddress(addr)
		gp, _ := backend.SuggestGasPrice(context.Background())
		tx2 := types.NewTransaction(nonce, to, value, 21000, gp.Mul(gp, common.Big2), nil)
		signedTx, _ := types.SignTx(tx2, types.LatestSignerForChainID(chainid), sk)
		if err := backend.SendTransaction(context.Background(), signedTx); err != nil {
			fmt.Printf("could not airdrop: %v\n", err)
			return false
		}
		tx = signedTx
	}
	// Wait for the last transaction to be mined
	bind.WaitMined(context.Background(), backend, tx)
	fmt.Printf("airdrop succesful\n")
	return true
}
