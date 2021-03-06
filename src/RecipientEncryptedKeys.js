import * as asn1js from "asn1js";
import { getParametersValue } from "pvutils";
import RecipientEncryptedKey from "./RecipientEncryptedKey";
//**************************************************************************************
export default class RecipientEncryptedKeys
{
	//**********************************************************************************
	/**
	 * Constructor for RecipientEncryptedKeys class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Array.<RecipientEncryptedKey>}
		 * @description encryptedKeys
		 */
		this.encryptedKeys = getParametersValue(parameters, "encryptedKeys", RecipientEncryptedKeys.defaultValues("encryptedKeys"));
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
			case "encryptedKeys":
				return [];
			default:
				throw new Error(`Invalid member name for RecipientEncryptedKeys class: ${memberName}`);
		}
	}
	//**********************************************************************************
	/**
	 * Compare values with default values for all class members
	 * @param {string} memberName String name for a class member
	 * @param {*} memberValue Value to compare with default value
	 */
	static compareWithDefault(memberName, memberValue)
	{
		switch(memberName)
		{
			case "encryptedKeys":
				return (memberValue.length === 0);
			default:
				throw new Error(`Invalid member name for RecipientEncryptedKeys class: ${memberName}`);
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
		//RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [RecipientEncryptedKeys]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new asn1js.Sequence({
			name: (names.blockName || ""),
			value: [
				new asn1js.Repeated({
					name: (names.RecipientEncryptedKeys || ""),
					value: RecipientEncryptedKey.schema()
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
			RecipientEncryptedKeys.schema({
				names: {
					RecipientEncryptedKeys: "RecipientEncryptedKeys"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for RecipientEncryptedKeys");
		//endregion

		//region Get internal properties from parsed schema
		this.encryptedKeys = Array.from(asn1.result.RecipientEncryptedKeys, element => new RecipientEncryptedKey({ schema: element }));
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
			value: Array.from(this.encryptedKeys, element => element.toSchema())
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
			encryptedKeys: Array.from(this.encryptedKeys, element => element.toJSON())
		};
	}
	//**********************************************************************************
}
//**************************************************************************************
