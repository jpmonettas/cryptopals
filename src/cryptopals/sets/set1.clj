(ns cryptopals.sets.set1
  (:require [clojure.math :as math]
            [clojure.test :refer [deftest is testing]]
            [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [java.math BigInteger]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Convert hex to base64 ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn hex-string-big-int [s]
  (BigInteger. s 16))

(def n->b64 (zipmap
             (range)
             (map char
                  (-> []
                      (into (range (int \A) (inc (int \Z))))
                      (into (range (int \a) (inc (int \z))))
                      (into (range (int \0) (inc (int \9))))
                      (into [(int \+) (int \/)])))))

(defn b64 [bi]
  (loop [b64-str ""
         n bi]
    (let [q (quot n 64)
          b64c (char (n->b64 (rem n 64)))
          b64-str (str b64c b64-str)]
      (if (zero? q)
        b64-str
        (recur b64-str q)))))


(deftest convert-hex-to-base-64-test
  (testing "Convert hex to base64"
    (is
     (= "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        (-> "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
            hex-string-big-int
            b64)))))


;;;;;;;;;;;;;;;
;; Fixed XOR ;;
;;;;;;;;;;;;;;;

(defn bytes-hex [bs]
  (let [bi (if (instance? java.math.BigInteger bs)
             bs
             (BigInteger. bs))]
    (format "%x" bi)))

(defn hex-string-bytes [s]
  (.toByteArray (hex-string-big-int s)))

(defn fixed-xor [bs1 bs2]
  (byte-array (map bit-xor bs1 bs2)))

(deftest fixed-xorg-test
  (testing "Fixed XOR"
    (is (= "746865206b696420646f6e277420706c6179"
           (bytes-hex
            (fixed-xor
             (hex-string-bytes "1c0111001f010100061a024b53535009181c")
             (hex-string-bytes "686974207468652062756c6c277320657965")))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Single-byte XOR cipher ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def english-char-vec-by-freq
  (->> (io/resource "alice_in_wonderland.txt")
       slurp
       str/lower-case
       frequencies
       (sort-by second >)
       (map first)))

(defn find-xor-key [bs]
  (let [eng-most-freq (first english-char-vec-by-freq)
        bs-most-freq  (->> (frequencies bs)
                           (sort-by second >)
                           ffirst
                           byte)]
    (bit-xor (byte eng-most-freq) (byte bs-most-freq))))

(defn decrypt-singe-byte-xor [s]
  (let [bs (hex-string-bytes s)
        xor-key (find-xor-key bs)]
    (String.
     (fixed-xor
      bs
      (byte-array (repeat (count bs) xor-key))))))

(deftest single-byte-xor-cipher
  (let [bs "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"]
    (testing "Single-byte XOR cipher"
      (is (= "Cooking MC's like a pound of bacon"
             (decrypt-singe-byte-xor bs))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Detect single-character XOR ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def data-4-lines
    (->> (io/resource "data-4.txt")
         slurp
         str/split-lines))

(defn print-all-decrypts [lines]

  (let [i (atom 0)]
    (doseq [l lines]
     (let [decrypt (decrypt-singe-byte-xor l)]
       (println decrypt ">>>>" l i)
       (swap! i inc)))))

(deftest detect-single-character-xor-line
  (testing "Detect single-character XOR"
    (let [found-line 170] ;; found by inspecting the output of (print-all-decrypts data-4-lines)
      (is (= "Now that the party is jumping\n"
             (decrypt-singe-byte-xor (get data-4-lines found-line)))))))
