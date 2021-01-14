package ssa;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;
/**
* @ClassName: PPSDA
* @Description: This is sample java code of PPSDA.
*/
public class PPSDA {
private final int MAXUSER = 500; // max user
private final int MAXRANGE = 10; // max range
private final int CERTAINTY = 64;
private int ModLength; // length in bits of the modulus n
private BigInteger p; // a random prime
private BigInteger q; // a random prime (distinct from p)
private BigInteger n; // n=p*q
private BigInteger pp; // a big prime pp=2*p*q+1
private BigInteger gn; // generator of Group G with order n
private BigInteger h0; // h0=g^q
private BigInteger h1; // h1=g^p
private BigInteger[] privatekeys; // private keys for users
private BigInteger[] c; // ci=g^mi*h1*H(t)^xi
private BigInteger d; // D
private BigInteger d1; // D1
private BigInteger d2; // D2
private BigInteger ht; // hash(time)
private int usersnumber; // user number
private int[] usercom; // user consumption
private int threshold; // threshold
private int max; // the max electricity consumption ofone user
private int mi; // mi
private int mj; // mj
private int ui; // ui
/**
* @ClassName: Datai
* @Description: This is a class for storing mi and ui.
*/
public class Datai {
private int mi;
private int ui;
public Datai(int mi, int ui) {
this.mi = mi;
this.ui = ui;
}
public int getMi() {
return mi;
}
public int getUi() {
return ui;
}
}
/**
* @ClassName: Dataj
* @Description: This is a class for storing mj.
*/
public class Dataj {
private int mj;
public Dataj(int mj) {
this.mj = mj;
}
public int getMj() {
return mj;
}
}
/**
* @param ModLengthIn
* the security parameter, which decides the
* length of large prime pp.
* @throws Exception
* If ModLengthIn<1024, there is an exception.
*/
public PPSD(int ModLengthIn) throws Exception {
if (ModLengthIn < 1024)
throw new Exception("PPSDA(int ModLength): "
+ "Length must be >= 1024");
mi = 0;
mj = 0;
ui = 0;
ht = hashTime(getCurrentTimeStamp());
this.ModLength = ModLengthIn;
generateKeys();
}
/**
* @Title: generateKeys
* @Description: This function is to generate keys.
* @return void
*/
public void generateKeys() {
p = new BigInteger(ModLength / 2 + 2, CERTAINTY,
new SecureRandom());
do {
q = new BigInteger(ModLength / 2, CERTAINTY,
new SecureRandom());
pp = BigInteger.valueOf(2).multiply(p).multiply(q)
.add(BigInteger.ONE);
if (pp.isProbablePrime(CERTAINTY)) {
BigInteger test = p.divide(q);
if (test.compareTo(BigInteger.valueOf(2)) == 1)
break;
}
} while (true);
n = p.multiply(q);
gn = getGeneratorFromZn(pp, p, q);
h0 = gn.modPow(q, pp);
h1 = gn.modPow(p, pp);
printallParameters();
}
/**
* @Title: initializeParameters
* @Description: This function is to initialize the
* related parameters.
* @param usernumber
* The number of users.
* @param threshold
* The threshold used to classify data.
* @param max
* The maximum electricity consumption for
* one user.
* @return void
*/
public void initializeParameters(int usersnumber, int
threshold, int max) {
this.usersnumber = usersnumber;
this.threshold = threshold;
this.max = max;
usercom = new int[this.usersnumber];
privatekeys = new BigInteger[this.usersnumber + 1];
c = new BigInteger[this.usersnumber];
}
/**
* @Title: getGeneratorFromZn
* @Description: This function is to get a generator
* from Z_n.
* @param pp
* A large prime, pp=2*p*q+1.
* @param p
* A large prime.
* @param q
* A large prime.
* @return BigInteger A generator of Z_n.
*/
private BigInteger getGeneratorFromZn(BigInteger pp,
BigInteger p, BigInteger q) {
BigInteger d;
BigInteger a, b, c;
BigInteger onetest = BigInteger.ONE;
do {
d = getRandomFromZpp();
a = d.modPow(BigInteger.valueOf(2), pp);
b = d.modPow(p, pp);
c = d.modPow(q, pp);
// satisfy the conditions
if (!a.equals(onetest) && !b.equals(onetest)
&& !c.equals(onetest)
&& d.gcd(pp).equals(onetest)) {
break;
}
} while (true);
return d.modPow(BigInteger.valueOf(2), pp);
}
/**
* @Title: getRandomFromZpp
* @Description: This function is to get a random
* value from Z_pp.
* @return BigInteger A random value in Z_pp.
*/
private BigInteger getRandomFromZpp() {
BigInteger r;
do {
r = new BigInteger(ModLength, new SecureRandom());
} while (r.compareTo(BigInteger.ZERO) <= 0 ||
r.compareTo(pp) >= 0);
return r;
}
/**
* @Title: getRandomFromZStarN
* @Description: This function is to get a random value
* from Z*_n.
* @return BigInteger A random value in Z*_n.
*/
private BigInteger getRandomFromZStarN() {
BigInteger r;
do {
r = new BigInteger(ModLength, new SecureRandom());
} while (r.compareTo(n) >= 0 || r.gcd(n)
.intValue() != 1);
return r;
}
/**
* @Title: printallParameters
* @Description: This function prints all related
* parameters
* @return void
*/
private void printallParameters() {
System.out.println("pp:" + pp.toString());
System.out.println("p: " + p.toString());
System.out.println("q: " + q.toString());
System.out.println("n: " + n.toString());
System.out.println("g: " + gn.toString());
System.out.println("h0: " + h0.toString());
System.out.println("h1: " + h1.toString());
}
/**
* @Title: findDatai
* @Description: This function use brute-force search to
* find the data.
* @param c1
* The input data.
* @return Datai The found data.
* @throws Exception
* If the data is not found, there is
* an exception.
*/
private Datai findDatai(BigInteger c1) throws Exception {
BigInteger exponent;
Datai data = null;
for (int i = 0; i <= MAXUSER; i++) {
for (int j = 0; j <= MAXUSER * MAXRANGE; j++) {
exponent = BigInteger.valueOf(j).add( 
		p.multiply(BigInteger.valueOf(i)));
		if (c1.compareTo(h1.modPow(exponent,
		pp)) == 0) {
		data = new Datai(j, i);
		return data;
		}
		}
		}
		throw new Exception("findDatai(BigInteger c1): "
		+ "cannot find the data.");
		}
		/**
		* @Title: findDataj
		* @Description: This function use brute-force search
		* to find the data.
		* @param c1
		* The input data.
		* @return Dataj The found data.
		* @throws Exception
		* If the data is not found, there is
		* an exception.
		*/
		private Dataj findDataj(BigInteger c2) throws Exception {
		for (int i = 0; i <= MAXUSER * MAXRANGE; i++) {
		if (c2.compareTo(h0.modPow(BigInteger.valueOf(i),
		pp)) == 0) {
		return new Dataj(i);
		}
		}
		throw new Exception("findDataj(BigInteger c2): "
		+ "cannot find the data.");
		}
		/**
		* @Title: generatePrivateKeysForUsers
		* @Description: This function generates the private keys
		* for each user.
		* @return void
		*/
		public void generatePrivateKeysForUsers() {
		BigInteger sum = BigInteger.ZERO;
		for (int i = 1; i < usersnumber + 1; i++) {
		privatekeys[i] = getRandomFromZStarN();
		sum = sum.add(privatekeys[i]);
		}
		privatekeys[0] = (BigInteger.ZERO.subtract(sum)).mod(n
		.multiply(BigInteger.valueOf(2)));
		}
		/**
		* @Title: getCurrentTimeStamp
		* @Description: This function returns the current
		* time stamp.
		* @return String The current time stamp, "yyyy-MM-dd
		* HH:mm:ss"
		*/
		private String getCurrentTimeStamp() {
		SimpleDateFormat sdfDate = new SimpleDateFormat
		("yyyy-MM-dd HH:mm:ss");
		Date now = new Date();
		String strDate = sdfDate.format(now);
		return strDate;
		}
		/**
		* @Title: hashTime
		* @Description: This function is a hash function,
		* which is used to hash the time.
		* @param time
		* The current time stamp.
		* @return BigInteger The hash value of time stamp.
		*/
		private BigInteger hashTime(String time) throws
		NoSuchAlgorithmException {
		MessageDigest md = MessageDigest
		.getInstance("SHA-256");
		md.update(time.getBytes());
		return new BigInteger(1, md.digest());
		}
		/**
		* @Title: generateUsersConsumption
		* @Description: This function is to generate the
		* consumption of each user.
		* @return void
		*/
		public void generateUsersConsumption() {
		Random random = new Random();
		int realmi = 0;
		int realmj = 0;
		int realui = 0;
		for (int i = 0; i < usersnumber; i++) {
		usercom[i] = random.nextInt(max);
		if (usercom[i] <= threshold) {
		realui++;
		realmi = realmi + usercom[i];
		} else {
		realmj = realmj + usercom[i];
		}
		}
		System.out.println("realmi, realmj, realui:" + realmi + " " + realmj
		+ " " + realui);
		}
		/**
		* @Title: enc
		* @Description: This function simulates the process
		* that user encrypt the
		* data and upload them.
		* @return void
		*/
		public void enc() {
		long enctime1 = System.currentTimeMillis();
		BigInteger tmp1; // g^mi
		BigInteger tmp2; // h1 h0^mi
		BigInteger tmp3; // H(t)^xi mod pp
		for (int i = 0; i < usersnumber; i++) {
		if (usercom[i] <= threshold) {
		tmp1 = gn.pow(usercom[i]);
		tmp2 = h1;
		tmp3 = ht.modPow(privatekeys[i + 1], pp);
		c[i] = (tmp1.multiply(tmp2).multiply(tmp3))
		.mod(pp);
		} else {
		tmp2 = h0.pow(usercom[i]);
		tmp3 = ht.modPow(privatekeys[i + 1], pp);
		c[i] = (tmp2.multiply(tmp3)).mod(pp);
		}
		}
		long enctime2 = System.currentTimeMillis();
		System.out.println("enc time cost: " + ((double)
		enctime2 - enctime1)/ usersnumber);
		}
		/**
		* @Title: dec
		* @Description: This function simulates the process that
		* gateway receive
		* these data and aggregate them, and then
		* control center can
		* decrypt them to get the final results.
		* @return void
		* @throws Exception
		* If the encrypted data cannot be decrypted,
		* there is an exception.
		*/
		public void dec() throws Exception {
		long aggtime1 = System.currentTimeMillis();
		BigInteger C = BigInteger.ONE;
		for (int i = 0; i < usersnumber; i++) {
		C = C.multiply(c[i]);
		}
		long aggtime2 = System.currentTimeMillis();
		System.out.println("agg cost time: "
		+ (aggtime2 - aggtime1)
		+ " usernumber: " + usersnumber);
		long dectime1 = System.currentTimeMillis();
		d = (C.mod(pp).multiply(ht.modPow(privatekeys[0],
		pp))).mod(pp);
		d1 = (d.modPow(p, pp)).mod(pp);
		Datai datai = findDatai(d1);
		mi = datai.getMi();
		ui = datai.getUi();
		d2 = d.multiply(gn.pow(mi).multiply(h1.pow(ui))
		.modInverse(pp)).mod(pp);
		Dataj dataj = findDataj(d2);
		mj = dataj.getMj();
		System.out.println("mi, mj, ui: " + mi + " " + mj
		+ " " + ui);
		long dectime2 = System.currentTimeMillis();
		System.out.println("dec cost time: " + (dectime2
		- dectime1)+ " usernumber: " + usersnumber);
		}
		// Simulation.
		public static void main(String[] args) {
		try {
		PPSD test = new PPSD(1024);
		int usernumber = 10;
		int maxelec = 10;
		System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
		int threshold = new Random().nextInt(10);
		System.out.println("threshold: " + threshold);
		test.initializeParameters(usernumber, threshold,
		maxelec);
		test.generatePrivateKeysForUsers();
		test.generateUsersConsumption();
		test.enc();
		test.dec();
		} catch (Exception e) {
		e.printStackTrace();
		}
		}
		}
