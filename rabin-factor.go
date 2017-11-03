package main

import (
  "fmt"
  "io/ioutil"
  "math/big"
 crypt "crypto/rand"
  "os"
  "log"
  "os/exec"
)

func main() {

  // ybig = y, and message = m
  public_key_filename := os.Args[1]

  factor1 := big.NewInt(0)

  N := ExtractDetailsFromPublicKeyFile(public_key_filename)

 for true {
      message := generateNumber()
      ciphertext := Encrypt(message,N)
      CipherTextInString := ciphertext.String()

      y := CallRabinCrack(public_key_filename, CipherTextInString)
      y1 := string(y)

      ybig := big.NewInt(0)
      ybig.SetString(y1,10)

      factor1 = checkModVals(ybig,message,N)
    //  fmt.Println("Got factor ",factor1)

      if ((factor1.Cmp(big.NewInt(0)) != 0) && (factor1.Cmp(big.NewInt(1)) != 0)) {

        break
      }
    }

factor2 := big.NewInt(0)
factor2 = factor2.Div(N,factor1)

fmt.Println(factor1,",", factor2)

}

func checkModVals(y *big.Int, m *big.Int, N *big.Int) (*big.Int) {

  z := big.NewInt(0)
  modulus1 := big.NewInt(0)
  modulus1 = modulus1.Mod(m,N)

  modulus2 := big.NewInt(0)
  modulus2 = modulus2.Mod(y,N)

  mMinusy := big.NewInt(0).Sub(m,y)

  //temp := big.NewInt(0)

  if (mMinusy.Cmp(big.NewInt(0)) == -1) {

    mMinusy.Abs(mMinusy)

  }

  if (modulus1.Cmp(modulus2) != 0) {

    //z := big.NewInt(0)
    z = z.GCD(nil,nil,mMinusy,N)
    return z

  }

  return z

}

func generateNumber() (*big.Int) {

  n := 64
  b := make([]byte, n)
  _, y := crypt.Read(b)
  if y != nil {
    fmt.Println("Some error")
  }

  z := big.NewInt(0)
  randomNumber := z.SetBytes(b)

  return randomNumber
}

func CallRabinCrack(public_key_filename string, ciphertext string) ([]byte) {

	cmd := exec.Command("./rabin-crack",public_key_filename,ciphertext)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}

	return stdoutStderr

}


func Encrypt(Message *big.Int, N *big.Int) (*big.Int) {

  exponentationComponent := big.NewInt(2)
  Ciphertext := squareAndMultiple(Message, exponentationComponent, N)
  return Ciphertext
}

func ExtractDetailsFromPublicKeyFile(file_name string) (*big.Int) {

  // In Rabin's crypto-system, N is the public key
  FileContent, err := ioutil.ReadFile(file_name)
  N := big.NewInt(0)

  if err != nil {
    fmt.Println(" Error readng data from the file")
  } else {

  NinString := string(FileContent)
  // Below statements to remove left and right bracket from the string
  NinString = NinString[1:(len(NinString) - 1)]


  boolError := false
  N, boolError = N.SetString(NinString,10)
  if boolError != true {
    fmt.Println(" Error in Set String")
    }

  }
  return N
}


func squareAndMultiple(a *big.Int, b *big.Int, c *big.Int) (*big.Int) {

  // FormatInt will provide the binary representation of a number
  binExp := fmt.Sprintf("%b", b)
  binExpLength := len(binExp)

  initialValue := big.NewInt(0)
  initialValue = initialValue.Mod(a,c)

  // Hold the initial value in result
  result := big.NewInt(0)
  result = result.Set(initialValue)

  // Using the square and multipy algorithm to perform modular exponentation
  for i := 1; i < binExpLength; i++ {

    // 49 is the ASCII representation of 1 and 48 is the ASCII representation
    // of 0
    interMediateResult := big.NewInt(0)
    interMediateResult = interMediateResult.Mul(result,result)
    result = result.Mod(interMediateResult, c)

    if byte(binExp[i]) == byte(49) {
      interResult := big.NewInt(0)
      interResult = interResult.Mul(result,initialValue)
      result = result.Mod(interResult, c)
    }
  }
  return result

}
