package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	//"fmt"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
)

// Implementation of RAPPOR client in Go.
// Based on exisiting implementation in python.
// Contains the encoder and necessary prelims, this doesn't return statistics (to do)

func main() {
}

type RAPPOR struct {
	// Encoding parameters:
	// k controls de size (bits) of the bloom filter
	// h is the number of bloom filter hash functions
	// m is the number of cohorts (each client is randomly assigned to a cohort)
	// p,q,f are the randomized response paramaters which control privacy levels
	k_bloombits, h_hashes, m_cohorts int
	p_prob, q_prob, f_prob           float64
}

func ParamsInit() RAPPOR {
	rappor := RAPPOR{16, 2, 64, 0.5, 0.75, 0.5}
	return rappor
}

func RapporJSON(_rappor RAPPOR) ([]byte, error) {
	jsonrappor, err := json.Marshal(_rappor)
	if err != nil {
		return nil, err
	}
	return jsonrappor, nil
}

// returns an n bit integer
// each bit is evaluated as bool(random int in [0.1000) < p(bit=1)*1000)
// where p*1000 is truncated when converted to big.Int
// so each bit has probability p (up to 3 decimals) of being 1
type SecureRandom struct {
	n_bits   int
	prob_one float64
}

func InitSecRand(_n int, _pone float64) SecureRandom {
	srand := SecureRandom{_n, _pone}
	return srand
}
func SecRand(_srand SecureRandom) int {
	var r uint = 0
	__p := big.NewInt(int64(_srand.prob_one * 1000.0))
	for i := 0; i < _srand.n_bits; i++ {
		rndm, err := rand.Int(rand.Reader, big.NewInt(1000))
		if err != nil {
			panic("something went wrong")
		}
		b := (rndm.Cmp(__p) < 0) //Cmp returns -1 if rndm<__p, 0 if rndm==__p, +1 if rndm>__p
		var bit int
		if b {
			bit = 1
		} else {
			bit = 0
		}
		r |= (uint(bit) << uint(i))
	}
	return int(r)
}

// Obtain IRR probabilities
type SecIrrRand struct {
	n_bits int
	p_gen  int
	q_gen  int
}

func InitSecIrrRand(_rappor RAPPOR) SecIrrRand {
	_srand := InitSecRand(_rappor.k_bloombits, _rappor.p_prob)
	__srand := InitSecRand(_rappor.k_bloombits, _rappor.q_prob)
	sirand := SecIrrRand{_rappor.k_bloombits, SecRand(_srand), SecRand(__srand)}
	return sirand
}

// convert an integer to a 4 byte big endian string for hashing
// don't really get the tehcnical reasoning behind this cause am retarded
// read the rappor code comments for actual information
func ConvToBigEndian(_i int) string {
	//___i := binary.BigEndian.String(strconv.Itoa(_i))
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(_i)) // converts to Uint32 (4 bytes) big endian
	return strconv.Itoa(int(_i))                // assuming this preserves endianess/4 byte?
}

func GetBloomBits(_word string, _m int, _h int, _k int) []int {
	val := ConvToBigEndian(_m) + _word //cohort m converted to 4 byte prefix
	hash := md5.Sum([]byte(val))
	if _h > len(hash) {
		panic("too many hash functions")
	}
	bits := make([]int, _h)
	for i := 0; i < _h; i++ {
		bits[i] = int(hash[i]) % _k
	}
	return bits
}

func GetPrrMasks(_key string, _word string, _f float64, _k int) (int, int) {
	hmc := hmac.New(sha256.New, []byte(_key))
	hmc.Write([]byte(_word))
	_hmc := hmc.Sum(nil)
	if len(_hmc) != 32 {
		panic("should be 32")
	}
	if _k > len(_hmc) {
		panic("bloom filter size too big (too many bits)")
	}
	threshold := _f * float64(128)
	uniform := uint(0)
	_f_mask := uint(0)
	for i := 0; i < _k; i++ {
		ubit := uint(_hmc[i]) & 0x01 // 1 bit of entropy
		uniform |= (ubit << uint(i))
		rand128 := uint(_hmc[i]) >> 1 // 7 bits of entropy
		noise := (float64(rand128) < threshold)
		var _noise uint
		if noise {
			_noise = 1
		} else {
			_noise = 0
		}
		_f_mask |= (_noise << uint(i))
	}
	return int(uniform), int(_f_mask)
}

func BitString(_irr int, _k int) string {
	bits := make([]uint, _k)
	for i := 0; i < _k; i++ {
		if (_irr & (1 << uint(i))) != 0 {
			bits[i] = 1

		} else {
			bits[i] = 0
		}
	}
	// repackage bits into a string, reversed
	stringbits := []string{}
	for i, j := 0, len(bits)-1; i < j; i, j = i+1, j-1 {
		stringbits[i] = strconv.Itoa(int(bits[j]))
		stringbits[j] = strconv.Itoa(int(bits[i]))
	}
	return strings.Join(stringbits, "")
}

// Obfuscates values for a given user using the RAPPOR privacy algorithm
type Encoder struct {
	rappor     RAPPOR
	cohort     int
	key        string
	secirrrand SecIrrRand
}

func InitEncoder(_rappor RAPPOR, _cohort int, _key string, _secirrrand SecIrrRand) Encoder {
	encoder := Encoder{_rappor, _cohort, _key, _secirrrand}
	return encoder
}

func InternalEncodeBits(_encoder Encoder, _bits []int) (int, int) {
	__bits := []string{}
	var err error
	for i := 0; i < len(_bits); i++ {
		__bits[i] = strconv.Itoa(_bits[i])
		if err != nil {
			panic("not good")
		}
	}
	___bits, errr := strconv.Atoi(strings.Join(__bits, ""))
	if errr != nil {
		panic("not good")
	}
	uniform, f_mask := GetPrrMasks(_encoder.key, ConvToBigEndian(___bits), _encoder.rappor.f_prob, _encoder.rappor.k_bloombits)
	prr := (___bits & ^f_mask) | (uniform & f_mask)
	p_bits := _encoder.secirrrand.p_gen
	q_bits := _encoder.secirrrand.q_gen
	irr := (p_bits & ^prr) | (q_bits & prr)
	return prr, irr
}

func InternalEncode(_word string, _encoder Encoder) (int, int, int) {
	bloom_bits := GetBloomBits(_word, _encoder.cohort, _encoder.rappor.h_hashes, _encoder.rappor.k_bloombits)
	bloom := 0
	for i := 0; i < len(bloom_bits); i++ {
		bloom |= (1 << uint(bloom_bits[i]))
	}
	_bloom := strconv.Itoa(bloom)
	__bloom := strings.Split(_bloom, "")
	___bloom := []int{}
	var errr error
	for i := 0; i < len(__bloom); i++ {
		___bloom[i], errr = strconv.Atoi(__bloom[i])
		if errr != nil {
			panic("not good")
		}
	}
	prr, irr := InternalEncodeBits(_encoder, ___bloom)
	return int(bloom), prr, irr
}

func EncodeBits(_bits []int, _encoder Encoder) int {
	_, irr := InternalEncodeBits(_encoder, _bits)
	return irr
}

func Encode(_encoder Encoder, _word string) int {
	_, _, irr := InternalEncode(_word, _encoder)
	return irr
}
