package utils

import (
	"strconv"

	"github.com/urfave/cli"

	"github.com/smallstep/cli-utils/errs"
	"go.step.sm/crypto/keyutil"
)

// DefaultRSASize sets the default key size for RSA to 2048 bits.
const DefaultRSASize = 2048

// DefaultECCurve sets the default curve for EC to P-256.
const DefaultECCurve = "P-256"

// GetKeyDetailsFromCLI gets the key pair algorithm, curve, and size inputs
// from the CLI context.
func GetKeyDetailsFromCLI(ctx *cli.Context, insecure bool, ktyKey, curveKey, sizeKey string) (string, string, int, error) {
	var (
		crv  = ctx.String("curve")
		size = ctx.Int("size")
		kty  = ctx.String("kty")
	)

	if ctx.IsSet(ktyKey) {
		switch kty {
		case "RSA":
			if !ctx.IsSet(sizeKey) {
				size = DefaultRSASize
			}
			if ctx.IsSet(curveKey) {
				return kty, crv, size, errs.IncompatibleFlagValue(ctx, curveKey, ktyKey, kty)
			}
			minimalSize := keyutil.MinRSAKeyBytes * 8
			if size < minimalSize && !insecure {
				return kty, crv, size, errs.MinSizeInsecureFlag(ctx, sizeKey, strconv.Itoa(minimalSize))
			}
			if size <= 0 {
				return kty, crv, size, errs.MinSizeFlag(ctx, sizeKey, "0")
			}
		case "EC":
			if ctx.IsSet("size") {
				return kty, crv, size, errs.IncompatibleFlagValue(ctx, sizeKey, ktyKey, kty)
			}
			if !ctx.IsSet("curve") {
				crv = DefaultECCurve
			}
			switch crv {
			case "P-256", "P-384", "P-521": // ok
			default:
				return kty, crv, size, errs.IncompatibleFlagValueWithFlagValue(ctx, ktyKey, kty,
					curveKey, crv, "P-256, P-384, P-521")
			}
		case "ML-DSA":
		if ctx.IsSet("size") {
			return kty, crv, size, errs.IncompatibleFlagValue(ctx, sizeKey, ktyKey, kty)
		}
		if !ctx.IsSet("curve") {
			crv = "65"
		}
		switch crv {
		case "44", "65", "87": // ok
		default:
			return kty, crv, size, errs.IncompatibleFlagValueWithFlagValue(ctx, ktyKey, kty,
				curveKey, crv, "44, 65, 87")
		}
	case "MLKEM":
		if ctx.IsSet("size") {
			return kty, crv, size, errs.IncompatibleFlagValue(ctx, sizeKey, ktyKey, kty)
		}
		if !ctx.IsSet("curve") {
			crv = "ML-KEM-768"
		}
		switch crv {
		case "ML-KEM-768", "ML-KEM-1024": // ok
		default:
			return kty, crv, size, errs.IncompatibleFlagValueWithFlagValue(ctx, ktyKey, kty,
				curveKey, crv, "ML-KEM-768, ML-KEM-1024")
		}
	case "OKP":
			if ctx.IsSet("size") {
				return kty, crv, size, errs.IncompatibleFlagValue(ctx, sizeKey, ktyKey, kty)
			}
			switch crv {
			case "Ed25519": // ok
			case "": // ok: OKP defaults to Ed25519
				crv = "Ed25519"
			default:
				return kty, crv, size, errs.IncompatibleFlagValueWithFlagValue(ctx, ktyKey, kty,
					curveKey, crv, "Ed25519")
			}
		default:
			return kty, crv, size, errs.InvalidFlagValue(ctx, ktyKey, kty, "RSA, EC, OKP, ML-DSA, MLKEM")
		}
	} else {
		if ctx.IsSet(curveKey) {
			return kty, crv, size, errs.RequiredWithFlag(ctx, curveKey, ktyKey)
		}
		if ctx.IsSet("size") {
			return kty, crv, size, errs.RequiredWithFlag(ctx, sizeKey, ktyKey)
		}
		// Set default key type | curve | size.
		kty = "EC"
		crv = "P-256"
		size = 0
	}
	return kty, crv, size, nil
}
