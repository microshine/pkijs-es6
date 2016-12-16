import * as asn1js from "asn1js";
import { getParametersValue } from "pvutils";
import AlgorithmIdentifier from "./AlgorithmIdentifier";
//**************************************************************************************
export default class PBKDF2Params
{
	//**********************************************************************************
	/**
	 * Constructor for PBKDF2Params class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Object}
		 * @description salt
		 */
		this.salt = getParametersValue(parameters, "salt", PBKDF2Params.defaultValues("salt"));
		/**
		 * @type {number}
		 * @description iterationCount
		 */
		this.iterationCount = getParametersValue(parameters, "iterationCount", PBKDF2Params.defaultValues("iterationCount"));
		/**
		 * @type {number}
		 * @description keyLength
		 */
		this.keyLength = getParametersValue(parameters, "keyLength", PBKDF2Params.defaultValues("keyLength"));
		/**
		 * @type {AlgorithmIdentifier}
		 * @description prf
		 */
		this.prf = getParametersValue(parameters, "prf", PBKDF2Params.defaultValues("prf"));
		//endregion

		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
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
			case "salt":
				return {};
			case "iterationCount":
				return (-1);
			case "keyLength":
				return 0;
			case "prf":
				return new AlgorithmIdentifier();
			default:
				throw new Error(`Invalid member name for PBKDF2Params class: ${memberName}`);
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
		//PBKDF2-params ::= SEQUENCE {
		//    salt CHOICE {
		//        specified OCTET STRING,
		//        otherSource AlgorithmIdentifier },
		//  iterationCount INTEGER (1..MAX),
		//  keyLength INTEGER (1..MAX) OPTIONAL,
		//  prf AlgorithmIdentifier
		//    DEFAULT { algorithm hMAC-SHA1, parameters NULL } }

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [saltPrimitive]
		 * @property {string} [saltConstructed]
		 * @property {string} [iterationCount]
		 * @property {string} [keyLength]
		 * @property {string} [prf]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new asn1js.Sequence({
			name: (names.blockName || ""),
			value: [
				new asn1js.Choice({
					value: [
						new asn1js.OctetString({ name: (names.saltPrimitive || "") }),
						AlgorithmIdentifier.schema(names.saltConstructed || {})
					]
				}),
				new asn1js.Integer({ name: (names.iterationCount || "") }),
				new asn1js.Integer({
					name: (names.keyLength || ""),
					optional: true
				}),
				AlgorithmIdentifier.schema(names.prf || {
					names: {
						optional: true
					}
				})
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
			PBKDF2Params.schema({
				names: {
					saltPrimitive: "salt",
					saltConstructed: {
						names: {
							blockName: "salt"
						}
					},
					iterationCount: "iterationCount",
					keyLength: "keyLength",
					prf: {
						names: {
							blockName: "prf",
							optional: true
						}
					}
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for PBKDF2_params");
		//endregion

		//region Get internal properties from parsed schema
		this.salt = asn1.result.salt;
		this.iterationCount = asn1.result.iterationCount.valueBlock.valueDec;

		if("keyLength" in asn1.result)
			this.keyLength = asn1.result.keyLength.valueBlock.valueDec;

		if("prf" in asn1.result)
			this.prf = new AlgorithmIdentifier({ schema: asn1.result.prf });
		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create array for output sequence 
		const outputArray = [];
		
		outputArray.push(this.salt);
		outputArray.push(new asn1js.Integer({ value: this.iterationCount }));
		
		if(PBKDF2Params.defaultValues("keyLength") !== this.keyLength)
			outputArray.push(new asn1js.Integer({ value: this.keyLength }));
		
		if(PBKDF2Params.defaultValues("prf").isEqual(this.prf) === false)
			outputArray.push(this.prf.toSchema());
		//endregion 
		
		//region Construct and return new ASN.1 schema for this object 
		return (new asn1js.Sequence({
			value: outputArray
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
		const _object = {
			salt: this.salt.toJSON(),
			iterationCount: this.iterationCount
		};

		if(PBKDF2Params.defaultValues("keyLength") !== this.keyLength)
			_object.keyLength = this.keyLength;

		if(PBKDF2Params.defaultValues("prf").isEqual(this.prf) === false)
			_object.prf = this.prf.toJSON();

		return _object;
	}
	//**********************************************************************************
}
//**************************************************************************************
