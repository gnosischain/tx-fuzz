package main

import (
	"context"
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MariusVanDerWijden/FuzzyVM/filler"
	txfuzz "github.com/MariusVanDerWijden/tx-fuzz"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

var (
	delay        = time.Second
	verbose      = false
	address      = "http://127.0.0.1:8545"
	txPerAccount = 1000
	airdropValue = new(big.Int).Mul(big.NewInt(100), big.NewInt(params.Ether))
	corpus       [][]byte
)

func main() {
	if len(os.Args) == 1 {
		fmt.Printf("%v <command> <rpc-url> <pvkey> <mnemonic> <start..end> <gas-price> [<hex-formatted-seed>] [<bool-access-list>]\n", os.Args[0])
		return
	}

	if len(os.Args) < 6 || len(os.Args) > 9 {
		panic("invalid amount of args, need from 6 to 9 args")
	}

	address = os.Args[2]
	// Override default value, just airdrop 0.0001 ETH
	//var airdropValue, ok = new(big.Int).SetString("100000000000000", 0)
	var airdropValue, ok = new(big.Int).SetString("100000000000", 0)
	fmt.Sprintf("%v", ok)

	txfuzz.SK = os.Args[3]
	sk := crypto.ToECDSAUnsafe(common.FromHex(txfuzz.SK))
	txfuzz.ADDR = crypto.PubkeyToAddress(sk.PublicKey).Hex()

	mnemonic := os.Args[4]

	startIdxStr, endIdxStr, isRange := strings.Cut(os.Args[5], "..")
	startIdx, err := strconv.Atoi(startIdxStr)
	if err != nil {
		panic(err)
	}
	endIdx := startIdx + 1
	if isRange {
		endIdx, err = strconv.Atoi(endIdxStr)
		if err != nil {
			panic(err)
		}
	}

	// Convert string to BigInt
	gasPrice, ok := new(big.Int).SetString(os.Args[6], 0)
	fmt.Sprintf("%v", ok)

	var seed *int64
	if len(os.Args) > 7 {
		a := common.LeftPadBytes(common.FromHex(os.Args[7]), 8)
		s := int64(binary.BigEndian.Uint64(a))
		seed = &s
	}

	al := false
	if len(os.Args) > 8 {
		alArg, err := strconv.ParseBool(os.Args[8])
		if err != nil {
			panic(err)
		}
		al = alArg
	}

	verbose = false
	if len(os.Args) > 9 {
		vArg, err := strconv.ParseBool(os.Args[9])
		if err != nil {
			panic(err)
		}
		verbose = vArg
	}

	initAccounts(mnemonic, startIdx, endIdx)
	// Disable watchBlocks() to circumvent `panic: notifications not supported`
	//watchBlocks()

	switch os.Args[1] {
	case "airdrop":
		airdrop(airdropValue)
	case "airdrop-spam":
		for airdrop(airdropValue) {
			SpamTransactions(uint64(txPerAccount), false, al, seed)
			time.Sleep(10 * time.Second)
		}
	case "spam":
		SpamTransactions(uint64(txPerAccount), false, al, seed)
	case "corpus":
		cp, err := readCorpusElements(os.Args[2])
		if err != nil {
			panic(err)
		}
		corpus = cp
		SpamTransactions(uint64(txPerAccount), true, al, seed)
	case "unstuck":
		unstuckTransactions()
	case "send":
		send()
	case "withdraw":
		withdraw(gasPrice)
	default:
		fmt.Println("unrecognized option")
	}
}

func SpamTransactions(N uint64, fromCorpus bool, accessList bool, seed *int64) {
	backend, _ := getRealBackend()
	var src rand.Rand
	if seed == nil {
		fmt.Println("No seed provided, creating one")
		rnd := make([]byte, 8)
		crand.Read(rnd)
		s := int64(binary.BigEndian.Uint64(rnd))
		seed = &s
	}
	src = *rand.New(rand.NewSource(*seed))
	fmt.Printf("Spamming transactions with seed: 0x%x\n", *seed)
	// Now let everyone spam baikal transactions
	var wg sync.WaitGroup
	wg.Add(len(keys))
	for i, key := range keys {
		// Set up the randomness
		random := make([]byte, 10000)
		src.Read(random)
		var f *filler.Filler
		if fromCorpus {
			elem := corpus[rand.Int31n(int32(len(corpus)))]
			f = filler.NewFiller(elem)
		} else {
			f = filler.NewFiller(random)
		}
		// Start a fuzzing thread
		go func(key *ecdsa.PrivateKey, addr common.Address, filler *filler.Filler) {
			defer wg.Done()
			SendBaikalTransactions(backend, key, f, addr, N, accessList)
		}(key, addrs[i], f)
	}
	wg.Wait()
}

func SendBaikalTransactions(client *rpc.Client, key *ecdsa.PrivateKey, f *filler.Filler, sender common.Address, N uint64, al bool) {
	backend := ethclient.NewClient(client)

	chainid, err := backend.ChainID(context.Background())
	if err != nil {
		panic(err)
	}

	for i := uint64(0); i < N; i++ {
		nonce, err := backend.NonceAt(context.Background(), sender, big.NewInt(-1))
		if err != nil {
			fmt.Printf("Could not get nonce: %v\n", err)
			continue
		}
		tx, err := txfuzz.RandomValidTx(client, f, sender, nonce, nil, chainid, al)
		if err != nil {
			if verbose {
				fmt.Printf("Could not create valid tx: %v\n", err)
			}
			continue
		}
		signedTx, err := types.SignTx(tx, types.NewLondonSigner(chainid), key)
		if err != nil {
			panic(err)
		}
		if err = backend.SendTransaction(context.Background(), signedTx); err != nil {
			if verbose {
				fmt.Printf("Could not send tx{sender: %v, nonce: %v}: %v\n", sender.Hex(), tx.Nonce(), err)
			}
			time.Sleep(time.Second)
			continue
		}
		time.Sleep(delay)
	}
}

func unstuckTransactions() {
	backend, _ := getRealBackend()
	client := ethclient.NewClient(backend)
	// Now let everyone spam baikal transactions
	var wg sync.WaitGroup
	wg.Add(len(keys))
	for i, key := range keys {
		go func(key *ecdsa.PrivateKey, addr common.Address) {
			defer wg.Done()
			unstuck(key, client, addr, addr, common.Big0, nil)
		}(key, addrs[i])
	}
	wg.Wait()
}

func readCorpusElements(path string) ([][]byte, error) {
	stats, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}
	corpus := make([][]byte, 0, len(stats))
	for _, file := range stats {
		b, err := ioutil.ReadFile(fmt.Sprintf("%v/%v", path, file.Name()))
		if err != nil {
			return nil, err
		}
		corpus = append(corpus, b)
	}
	return corpus, nil
}

func send() {
	backend, _ := getRealBackend()
	client := ethclient.NewClient(backend)
	to := common.HexToAddress(txfuzz.ADDR)
	sk := crypto.ToECDSAUnsafe(common.FromHex(txfuzz.SK2))
	value := new(big.Int).Mul(big.NewInt(100000), big.NewInt(params.Ether))
	sendTx(sk, client, to, value)
}