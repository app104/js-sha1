/*
 * [js-sha1]{@link https://github.com/app104/js-sha1}
 *
 * @version 1.0.0
 * @author septem jsm920@outlook.com
 * @copyright septem 2023
 * @note base on RFC 3174 US Secure Hash Algorithm 1 (SHA1)
 * @license SEM
 * Send an E-mail and Mark  
 * You can use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, 
 * before you Send an E-mail to author and tell what project you will use. And Mark the name in you project.
 * @usage
 * let sha1 = new SHA1("abc");
 * sha1.update("def");
 * let hash = sha1.final();
 * console.log(hash); //output 40Byte hex hash string
 * // or do like this
 * console.log(SHA1.sha1("abcdef"));
 */
class SHA1{
    #H = new Uint32Array([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]); //初始值
    #M = new Uint8Array(64); // 保存小于 512Bits(64Bytes) 以等待后续一起计算 sha1
    #C = [0, 0]; //count[0]保存 在buffer中等待执行的字符串, count[1]保存已执行的总数
    static #HEX='0123456789abcdef';
    /**
     * 计算 msg的 sha1
     * @param msg 
     */
    constructor(msg:string|Uint8Array|null=null){
        if(msg){this.update(msg);}
    }
    /**
     * 更新字符串
     * @param msg 
     */
    update(msg:string|Uint8Array){
        let arr:Uint8Array =  msg as Uint8Array;
        if(Object.getPrototypeOf(msg) == String.prototype){
            arr = new Uint8Array((msg as string).length);
            for(let i = 0; i != (msg as string).length; i++){
                arr[i] = (msg as string).charCodeAt(i);
            }
        }else if(Object.getPrototypeOf(msg) == ArrayBuffer.prototype){
            if(Object.getPrototypeOf(msg) != Uint8Array.prototype){
                arr = new Uint8Array(msg as ArrayBuffer);
            }
        }
        let t = this.#C[0];
        let s = 0;
        if(this.#C[0] || arr.length <= 64- this.#C[0]){//如果
            for( ; t != 64 && s != arr.length; t++,s++){
                this.#M[t] = arr[s];
            }
            this.#C[0] = t;
        }
        if (t == 64){
            this.#transform(this.#M);this.#C[0] = 0;
        }
        while(arr.length - s >= 64){
            this.#transform(arr, s); s+=64;
        }
        if(s < arr.length){
            for(t=0 ; t != 64 && s != arr.length; t++,s++){
                this.#M[t] = arr[s];
            }
            this.#C[0] = t;
        }
    }
    /**
     * 获取 SHA1 字符串的 sha1 结果
     * @returns 40Bytes Hex sha1 
     */
    final():string{
        let fill_bits = ()=>{
            for(let i = 63; i >=56 && bits; i--){
                this.#M[i] = bits & 0xFF; bits>>>=8;
            }
        }
        let bits = (this.#C[1]+this.#C[0])*8;
        this.#M[this.#C[0]] = 0x80;  for(let i = this.#C[0]+1; i < 64; i++){ this.#M[i] = 0; }
        if(this.#C[0] < 56){ //448bits == 56bytes
            fill_bits();
            this.#transform(this.#M);
        }else{
            this.#transform(this.#M);
            for(let i = 0; i < 56; i++){ this.#M[i] = 0; }
            fill_bits();
            this.#transform(this.#M);
        }
        let str:string = "";
        for(let i =0; i != this.#H.length; i++){
            let h = this.#H[i]; for(let j = 28; j >=0; j-=4) {str += SHA1.#HEX[(h >>> j) & 0x0F];}
        }
        return str;
    }
    /**
     * 静态函数, 获取 msg 的 sha1
     * @param msg 
     * @returns 
     */
    static sha1(msg:string|Uint8Array){
        let s = new SHA1(msg);
        return s.final();
        
    }
    /**每512位,即64个字节处理一次 */
    #transform(msg:Uint8Array, offset:number = 0){
        let S = function(n:number,X:number){return ((X<<n)|(X>>>(32-n)));}; //S^n(X)  =  (X << n) OR (X >> 32-n).
        let M = new Uint32Array(16); 
        let W = new Uint32Array(80);
        for(let i = 0; i != 16; i++){
            M[i] = ((msg[4*i + offset]<<24) | (msg[4*i+1 + offset]<<16) | (msg[4*i+2 + offset]<<8) | msg[4*i+3 + offset]);
            W[i] = M[i];
        }
        for(let t = 16; t != 80; t++){
            W[t] = S(1,(W[t-3]^ W[t-8] ^ W[t-14] ^ W[t-16])); ///W(t) = S^1(W(t-3) XOR W(t-8) XOR W(t-14) XOR W(t-16)).
        }
        let A = this.#H[0];let B = this.#H[1];let C = this.#H[2];let D = this.#H[3];let E = this.#H[4];
        for(let t =0; t!=20;t++){
            let TEMP = S(5,A) + ((B&C)|((~B)&D)) + E +W[t] + 0x5A827999; // K(t) = 5A827999         ( 0 <= t <= 19)// f(t;B,C,D) = (B AND C) OR ((NOT B) AND D)         ( 0 <= t <= 19)
            E = D;  D = C;  C = S(30,B);  B = A; A = TEMP; // TEMP = S^5(A) + f(t;B,C,D) + E + W(t) + K(t); E = D;  D = C;  C = S^30(B);  B = A; A = TEMP;
        }
        for(let t =20; t!=40;t++){
            let TEMP = S(5,A) + (B^C^D) + E +W[t] + 0x6ED9EBA1; // K(t) = 6ED9EBA1         (20 <= t <= 39) // f(t;B,C,D) = B XOR C XOR D                        (20 <= t <= 39)
            E = D;  D = C;  C = S(30,B);  B = A; A = TEMP; // TEMP = S^5(A) + f(t;B,C,D) + E + W(t) + K(t);  E = D;  D = C;  C = S^30(B);  B = A; A = TEMP;
        }
        for(let t =40; t!=60;t++){
            let TEMP = S(5,A) + ((B&C)|(B&D)|(C&D)) + E +W[t] + 0x8F1BBCDC; // K(t) = 8F1BBCDC  (20 <= t <= 39)// f(t;B,C,D) = (B AND C) OR (B AND D) OR (C AND D)  (40 <= t <= 59)
            E = D;  D = C;  C = S(30,B);  B = A; A = TEMP; //TEMP = S^5(A) + f(t;B,C,D) + E + W(t) + K(t);  E = D;  D = C;  C = S^30(B);  B = A; A = TEMP;
        }
        for(let t =60; t!=80;t++){
            let TEMP = S(5,A) + (B^C^D) + E +W[t] + 0xCA62C1D6; // K(t) = CA62C1D6         (20 <= t <= 39)// f(t;B,C,D) = B XOR C XOR D                        (60 <= t <= 79).
            E = D;  D = C;  C = S(30,B);  B = A; A = TEMP; // TEMP = S^5(A) + f(t;B,C,D) + E + W(t) + K(t); E = D;  D = C;  C = S^30(B);  B = A; A = TEMP;
        }
        this.#H[0] += A;this.#H[1] += B;this.#H[2] += C;this.#H[3] += D;this.#H[4] += E; //Let H0 = H0 + A, H1 = H1 + B, H2 = H2 + C, H3 = H3 + D, H4 = H4 + E.
        this.#C[1] +=64; //又完成64字节的计算
    }
};
