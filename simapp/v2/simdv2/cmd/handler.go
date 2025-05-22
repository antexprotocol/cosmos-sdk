package cmd

import (
	"context"
	"fmt"

	"cosmossdk.io/core/transaction"
	"cosmossdk.io/server/v2/cometbft/handlers"
	stakingtypes "cosmossdk.io/x/staking/types"
	v1 "github.com/cometbft/cometbft/api/cometbft/abci/v1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
)

func CustomPrepareProposal[T transaction.Tx]() handlers.PrepareHandler[T] {
	return func(ctx context.Context, app handlers.AppManager[T], codec transaction.Codec[T], req *v1.PrepareProposalRequest, chainID string) ([]T, error) {
		fmt.Printf("CustomPrepareProposal, txs: %v\n", len(req.Txs))
		var txs []T
		for _, tx := range req.Txs {
			decTx, err := codec.Decode(tx)
			if err != nil {
				fmt.Println("CustomPrepareProposal error decoding tx", err)
				continue
			}

			txs = append(txs, decTx)
		}

		// "Process" vote extensions (we'll just inject all votes)
		// injectedTx, err := json.Marshal(req.LocalLastCommit)
		// if err != nil {
		// 	return nil, err
		// }

		// // put the injected tx into the first position
		// txs = append([]T{cometbft.RawTx(injectedTx).(T)}, txs...)
		fmt.Printf("CustomPrepareProposal appended, txs: %v\n", len(txs))

		return txs, nil
	}
}

func CustomProcessProposalHandler[T transaction.Tx]() handlers.ProcessHandler[T] {
	return func(ctx context.Context, am handlers.AppManager[T], c transaction.Codec[T], req *v1.ProcessProposalRequest, chainID string) error {
		// Get all vote extensions from the first tx

		// injectedTx := req.Txs[0]
		// var voteExts v1.ExtendedCommitInfo
		// if err := json.Unmarshal(injectedTx, &voteExts); err != nil {
		// 	return err
		// }

		// Get validators from the staking module
		res, err := am.Query(
			ctx,
			0,
			&stakingtypes.QueryValidatorsRequest{},
		)
		if err != nil {
			return err
		}

		validatorsResponse := res.(*stakingtypes.QueryValidatorsResponse)
		consAddrToPubkey := map[string]cryptotypes.PubKey{}

		for _, val := range validatorsResponse.GetValidators() {
			cv := val.ConsensusPubkey.GetCachedValue()
			if cv == nil {
				return fmt.Errorf("public key cached value is nil")
			}

			cpk, ok := cv.(cryptotypes.PubKey)
			if ok {
				consAddrToPubkey[string(cpk.Address().Bytes())] = cpk
			} else {
				return fmt.Errorf("invalid public key type")
			}
		}

		// First verify that the vote extensions injected by the proposer are correct
		// if err := cometbft.ValidateVoteExtensions(
		// 	ctx,
		// 	am,
		// 	chainID,
		// 	func(ctx context.Context, b []byte) (cryptotypes.PubKey, error) {
		// 		if _, ok := consAddrToPubkey[string(b)]; !ok {
		// 			return nil, fmt.Errorf("validator not found")
		// 		}
		// 		return consAddrToPubkey[string(b)], nil
		// 	},
		// 	voteExts,
		// 	req.Height,
		// 	&req.ProposedLastCommit,
		// ); err != nil {
		// 	return err
		// }

		// TODO: do something with the vote extensions

		return nil
	}
}
