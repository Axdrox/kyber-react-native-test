global.Buffer = require('buffer').Buffer;
import React, { useEffect, useState } from 'react';
import { StyleSheet, Text, View, Button, Alert, TextInput, ScrollView } from 'react-native';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';

import CryptoES from 'crypto-es';


const kyber = require('crystals-kyber');


//const hash = CryptoES.SHA3("Message");
//console.log(hash);

function generarClavesKyber() {
  // Para generar un par de claves pública y privada (pk, sk)
  let pk_sk = kyber.KeyGen1024();
  let pk = pk_sk[0];
  let sk = pk_sk[1];

  // Generar una clave simétrica aleatoria de 256 bits (ss) y su encapsulación (c)
  let c_ss = kyber.Encrypt1024(pk);
  let c = c_ss[0];
  let ss1 = c_ss[1];

  // Para decapsular y obtener la misma clave simétrica
  let ss2 = kyber.Decrypt1024(c, sk);

  return { ss1, ss2 };
}

//Se puede ver la longitud del buffer, regresa el tamaño en bytes
//console.log(ss1.length);
//console.log(ss1);

//Comparación de tamaño de la clave con encode de hex o base64
/*
  const publicKeytoHex = Array.from(pk).map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase()
  const sharedSecretToHex_1 = Array.from(ss1).map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase()
  const sharedSecretToHex_2 = Array.from(ss2).map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase()
  console.log(publicKeytoHex.length);
  console.log(Buffer.from(pk).toString('base64').length);
  console.log("Shared Secret 1: ", sharedSecretToHex_1);
  console.log("Shared Secret 2: ", sharedSecretToHex_2);
*/

//    COMPARAR ARREGLOS
function ArrayCompare(a, b) {
  // check array lengths
  if (a.length != b.length) {
    return 0;
  }
  // check contents
  for (let i = 0; i < a.length; i++) {
    if (a[i] != b[i]) {
      return 0;
    }
  }
  return 1;
}
/*
  let result
  if (ArrayCompare(ss1, ss2))
    result = "Las claves simétricas son identicas, ¡¡¡ÉXITO!!! 😄"
  else
    result = "Las claves simétricas son diferentes, ¡FALLÓ! 😞"

  console.log(result);
*/

// Test function with KATs
//kyber.Test768();

/*
const encrypted = CryptoES.AES.encrypt("Message", sharedSecretToHex_1);
const decrypted = CryptoES.AES.decrypt(encrypted, sharedSecretToHex_2);
console.log("CIFRADO: " + encrypted);
console.log("DESCIFRADO: " + decrypted.toString(CryptoES.enc.Utf8));
console.log(encrypted.salt.toString())
*/

//const key = CryptoES.enc.Hex.parse(sharedSecretToHex_1);

// CIFRADO SIMÉTRICO
/*
  const iv = CryptoES.enc.Hex.parse('101112131415161718191a1b1c1d1e1f');

  const encrypted2 = CryptoES.AES.encrypt("Hola cómo estás, mi nombre es Alejandro", ss1, { iv: iv, mode: CryptoES.mode.CBC });
  console.log("TEXTO CIFRADO B64: "+encrypted2.ciphertext.toString(CryptoES.enc.Base64));

  const ciphertext = encrypted2.ciphertext.toString(CryptoES.enc.Base64);
  console.log("tipo: " + typeof (ciphertext));


  const words = CryptoES.enc.Base64.parse(ciphertext);
  const decrypted2 = CryptoES.AES.decrypt({ ciphertext: words }, ss2, { iv: iv });
  console.log("DESCIFRADO: " + decrypted2.toString(CryptoES.enc.Utf8));
*/


function cifrarAES(textoClaro, ss1) {
  //Para dejar la clave compartida en objeto del tipo WordArray
  const wordsClaveCompartida = CryptoES.lib.WordArray.create(ss1);

  // Para generar la sal
  let fecha2 = new Date;
  let entradaHash = "P" + fecha2.getDate().toString() + "Q" + fecha2.getMonth() + fecha2.getFullYear() + "C" + fecha2.getHours();
  const salt = CryptoES.MD5(entradaHash);

  // Generar la clave simetrica de 128 bits
  const key128Bits = CryptoES.PBKDF2(wordsClaveCompartida, salt, { keySize: 128 / 32 });

  console.log("Clave simétrica para cifrar: " + key128Bits.toString(CryptoES.enc.Base64));

  // Para generar el vector de inicializacion (IV)
  let fecha = new Date;
  let entradaHash2 = fecha.getDate().toString() + fecha.getMonth() + fecha.getFullYear() + fecha.getHours();
  const iv = CryptoES.MD5(entradaHash2);

  // Cifrar el texto en claro
  return CryptoES.AES.encrypt(textoClaro, key128Bits, { iv: iv, mode: CryptoES.mode.CTR }).ciphertext.toString(CryptoES.enc.Base64);
}

function descifrarAES(textoCifrado, ss2) {
  // Convierte el texto cifrado de base 64 a un objeto WordArray
  const wordsTextoCifrado = CryptoES.enc.Base64.parse(textoCifrado);

  //Para dejar la clave compartida en objeto del tipo WordArray
  const key = CryptoES.lib.WordArray.create(ss2);

  // Para generar la misma sal y obtener la misma clave
  let fecha2 = new Date;
  let entradaHash = "P" + fecha2.getDate().toString() + "Q" + fecha2.getMonth() + fecha2.getFullYear() + "C" + fecha2.getHours();
  const salt = CryptoES.MD5(entradaHash);

  // Generar la clave simetrica de 128 bits
  const key128Bits = CryptoES.PBKDF2(key, salt, { keySize: 128 / 32 });

  console.log("Clave simétrica para descifrar: " + key128Bits.toString(CryptoES.enc.Base64));

  // Para generar el vector de inicializacion (IV)
  let fecha = new Date;
  let entradaHash2 = fecha.getDate().toString() + fecha.getMonth() + fecha.getFullYear() + fecha.getHours();
  const iv = CryptoES.MD5(entradaHash2);

  // Descifrar el texto cifrado y codificarlo en UTF-8
  return CryptoES.AES.decrypt({ ciphertext: wordsTextoCifrado }, key128Bits, { iv: iv, mode: CryptoES.mode.CTR }).toString(CryptoES.enc.Utf8);
}


export default function App() {

  //Variables de estado
  /*
    const [clavePk, setPk] = useState();
    const [claveSk, setSk] = useState();
    const [claveEncapsulado, setEncapsulado] = useState();
    const [resultadoClaves, setResultadoClaves] = useState();
  */
  const [secretoCompartido_1, setSecretoCompartido_1] = useState();
  const [secretoCompartido_2, setSecretoCompartido_2] = useState();
  const [textoClaro, setTextoClaro] = useState();
  const [textoCifradoAES, setTextoCifradoAES] = useState();
  const [textoDescifradoAES, setTextoDescifradoAES] = useState();

  /*
    const clavePk_base64 = Buffer.from(pk).toString('base64');
    const claveSk_base64 = Buffer.from(sk).toString('base64');
    const encapsulado_base64 = Buffer.from(c).toString('base64');
  */

  /*
    AGREGAR EN FUNCIÓN ONPRESS DE BOTÓN

        <Text>Clave pública Kyber:{"\n"}{clavePk}{"\n"}{"\n"}</Text>

        <Text>Clave privada Kyber:{"\n"}{claveSk}{"\n"}{"\n"}</Text>

        <Text>Encapsulado de clave:{"\n"}{claveEncapsulado}{"\n"}{"\n"}</Text>
  */
  let claveSimetricas;
  return (
    <SafeAreaProvider style={styles.container}>
      <SafeAreaView>
        <ScrollView>
          <Text> CRYSTALS-KYBER TEST </Text>

          <Button
            title="Generar claves de Kyber"
            onPress={() => {
              //Para observar las claves públicas y privadas de Kyber, así como el encapsulado
              /*
              setPk(clavePk_base64),
                setSk(claveSk_base64),
                setEncapsulado(encapsulado_base64),
                */

              //let { ss1, ss2 } = generarClavesKyber();

              this.claveSimetricas = generarClavesKyber();
              let ss1 = this.claveSimetricas.ss1,
                ss2 = this.claveSimetricas.ss2;

              const secretoCompartido_1_base64 = Buffer.from(ss1).toString('base64');
              const secretoCompartido_2_base64 = Buffer.from(ss2).toString('base64');
              setSecretoCompartido_1(secretoCompartido_1_base64);
              setSecretoCompartido_2(secretoCompartido_2_base64);

              //setResultadoClaves(ArrayCompare(secretoCompartido_1, secretoCompartido_2)?"Claves simétricas iguales. ✅":"Claves simétricas no coinciden.");
              //<Text>Resultado: {"\n"}{resultadoClaves}{"\n"}{"\n"}</Text>

              setTextoCifradoAES("");
              setTextoDescifradoAES("");
            }}
          />

          <Text>Clave compartida 1:{"\n"}{secretoCompartido_1}{"\n"}</Text>
          <Text>Clave compartida 2:{"\n"}{secretoCompartido_2}{"\n"}</Text>

          <TextInput style={styles.textInput} placeholder='Escribe algo'
            onChangeText={(textoClaro) => {
              setTextoClaro(textoClaro),
                setTextoCifradoAES(""),
                setTextoDescifradoAES("")
            }}>
          </TextInput>

          <Button
            title="Cifrar con AES"
            onPress={() => {
              let ss1 = this.claveSimetricas.ss1;
              //const startTime = performance.now();
              setTextoCifradoAES(cifrarAES(textoClaro, ss1));
              //const endTime = performance.now();

              //const executionTime = endTime - startTime;
              //console.log('Execution time:', executionTime, 'milliseconds');

              //Limpiar
              setTextoDescifradoAES("");
            }}
          />
          <Text>{textoCifradoAES}</Text>

          <Button
            title="Descifrar con AES"
            onPress={() => {
              let ss2 = this.claveSimetricas.ss2;
              try {
                setTextoDescifradoAES(descifrarAES(textoCifradoAES, ss2));
              }
              catch (e) {

              }
            }}
          />
          <Text>{textoDescifradoAES}</Text>

        </ScrollView>
      </SafeAreaView>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  textInput: {
    borderWidth: 1,
    borderRadius: 10,
    padding: 10,
    margin: 10

  }
});