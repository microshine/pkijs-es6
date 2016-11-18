import * as asn1js from "asn1js";
import { getParametersValue } from "pvutils";
import SafeBag from "pkijs/src/SafeBag";
//**************************************************************************************
export default class SafeContents
{
	//**********************************************************************************
	/**
	 * Constructor for SafeContents class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Array.<SafeBag>}
		 * @description safeBags
		 */
		this.safeBags = getParametersValue(parameters, "safeBags", SafeContents.defaultValues("safeBags"));
		/**
		 * @type {number}
		 * @description privacyMode 0 - "no privacy" mode, 1 - "password-based privacy" mode, 2 - "certificate-based privacy" mode
		 */
		this.privacyMode = getParametersValue(parameters, "privacyMode", SafeContents.defaultValues("privacyMode"));
		/**
		 * @type {Object}
		 * @description privacyParameters
		 */
		this.privacyParameters = getParametersValue(parameters, "privacyParameters", SafeContents.defaultValues("privacyParameters"));
		//endregion
		
		//region If input argument array contains "schema" for this object
		if("schema" in parameters)
			this.fromSchema(parameters.schema);
		//endregion
		
		//region If input argument array contains "contentInfo" for this object
		if("contentInfo" in parameters)
			this.fromContentInfo(parameters.contentInfo);
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
			case "safeBags":
				return [];
			case "privacyMode":
				return 0;
			case "privacyParameters":
				return {};
			default:
				throw new Error(`Invalid member name for SafeContents class: ${memberName}`);
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
			case "safeBags":
				return (memberValue.length === 0);
			case "privacyMode":
				return (memberValue === SafeContents.defaultValues(memberName));
			case "privacyParameters":
				return ((memberValue instanceof Object) && (Object.keys(memberValue).length === 0));
			default:
				throw new Error(`Invalid member name for SafeContents class: ${memberName}`);
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
		//SafeContents ::= SEQUENCE OF SafeBag
		
		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [safeBags]
		 */
		const names = getParametersValue(parameters, "names", {});
		
		return (new asn1js.Sequence({
			name: (names.blockName || ""),
			value: [
				new asn1js.Repeated({
					name: (names.safeBags || ""),
					value: SafeBag.schema()
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
			SafeContents.schema({
				names: {
					safeBags: "safeBags"
				}
			})
		);
		
		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for SafeContents");
		//endregion
		
		//region Get internal properties from parsed schema
		this.safeBags = Array.from(asn1.result.safeBags, element => new SafeBag({ schema: element }));
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
			value: Array.from(this.safeBags, element => element.toSchema())
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
			safeBags: Array.from(this.safeBags, element => element.toJSON())
		};
	}
	//**********************************************************************************
}
//**************************************************************************************