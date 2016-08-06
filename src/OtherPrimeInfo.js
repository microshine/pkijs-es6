import * as asn1js from "asn1js";
import { getParametersValue, toBase64, arrayBufferToString, stringToArrayBuffer, fromBase64 } from "pvutils";
//**************************************************************************************
export default class OtherPrimeInfo
{
	//**********************************************************************************
	/**
	 * Constructor for OtherPrimeInfo class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Integer}
		 * @description prime
		 */
		this.prime = getParametersValue(parameters, "prime", OtherPrimeInfo.defaultValues("prime"));
		/**
		 * @type {Integer}
		 * @description exponent
		 */
		this.exponent = getParametersValue(parameters, "exponent", OtherPrimeInfo.defaultValues("exponent"));
		/**
		 * @type {Integer}
		 * @description coefficient
		 */
		this.coefficient = getParametersValue(parameters, "coefficient", OtherPrimeInfo.defaultValues("coefficient"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
		//region If input argument array contains "json" for this object
		if("json" in parameters)
			this.fromJSON(parameters.json);
		//endregion
	}
	//**********************************************************************************
	/**
	 * Return default values for all class members
	 * @param {string} memberName String name for a class member
	 */
	static defaultValues(memberName)
	{
		switch(memberName)
		{
			case "prime":
				return new asn1js.Integer();
			case "exponent":
				return new asn1js.Integer();
			case "coefficient":
				return new asn1js.Integer();
			default:
				throw new Error(`Invalid member name for OtherPrimeInfo class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Return value of asn1js schema for current class
	 * @param {Object} parameters Input parameters for the schema
	 * @returns {Object} asn1js schema object
	 */
	static schema(parameters = {})
	{
		//OtherPrimeInfo ::= Sequence {
		//    prime             Integer,  -- ri
		//    exponent          Integer,  -- di
		//    coefficient       Integer   -- ti
		//}

		/**
		 * @type {Object}
		 * @property {string} prime
		 * @property {string} exponent
		 * @property {string} coefficient
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new asn1js.Sequence({
			name: (names.blockName || ""),
			value: [
				new asn1js.Integer({ name: (names.prime || "") }),
				new asn1js.Integer({ name: (names.exponent || "") }),
				new asn1js.Integer({ name: (names.coefficient || "") })
			]
		}));
	}
	//**********************************************************************************
	/**
	 * Convert parsed asn1js object into current class
	 * @param {!Object} schema
	 */
	fromSchema(schema)
	{
		//region Check the schema is valid
		const asn1 = asn1js.compareSchema(schema,
			schema,
			OtherPrimeInfo.schema({
				names: {
					prime: "prime",
					exponent: "exponent",
					coefficient: "coefficient"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for OtherPrimeInfo");
		//endregion

		//region Get internal properties from parsed schema
		this.prime = asn1.result.prime.convertFromDER();
		this.exponent = asn1.result.exponent.convertFromDER();
		this.coefficient = asn1.result.coefficient.convertFromDER();
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Construct and return new ASN.1 schema for this object
		return (new asn1js.Sequence({
			value: [
				this.prime.convertToDER(),
				this.exponent.convertToDER(),
				this.coefficient.convertToDER()
			]
		}));
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convertion for the class to JSON object
	 * @returns {Object}
	 */
	toJSON()
	{
		return {
			r: toBase64(arrayBufferToString(this.prime.valueBlock.valueHex), true, true),
			d: toBase64(arrayBufferToString(this.exponent.valueBlock.valueHex), true, true),
			t: toBase64(arrayBufferToString(this.coefficient.valueBlock.valueHex), true, true)
		};
	}
	//**********************************************************************************
	/**
	 * Convert JSON value into current object
	 * @param {Object} json
	 */
	fromJSON(json)
	{
		if("r" in json)
			this.prime = new asn1js.Integer({ valueHex: stringToArrayBuffer(fromBase64(json.r, true)) });
		else
			throw new Error("Absent mandatory parameter \"r\"");

		if("d" in json)
			this.exponent = new asn1js.Integer({ valueHex: stringToArrayBuffer(fromBase64(json.d, true)) });
		else
			throw new Error("Absent mandatory parameter \"d\"");

		if("t" in json)
			this.coefficient = new asn1js.Integer({ valueHex: stringToArrayBuffer(fromBase64(json.t, true)) });
		else
			throw new Error("Absent mandatory parameter \"t\"");
	}
	//**********************************************************************************
}
//**************************************************************************************
