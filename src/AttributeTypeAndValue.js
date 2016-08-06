import * as asn1js from "asn1js";
import { getParametersValue } from "pvutils";
//**************************************************************************************
export default class AttributeTypeAndValue
{
	//**********************************************************************************
	/**
	 * Constructor for AttributeTypeAndValue class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {number}
		 * @description 0 - UTCTime; 1 - GeneralizedTime; 2 - empty value
		 */
		this.type = getParametersValue(parameters, "type", AttributeTypeAndValue.defaultValues("type"));
		/**
		 * @type {Object}
		 * @description Value of the TIME class
		 */
		this.value = getParametersValue(parameters, "value", AttributeTypeAndValue.defaultValues("value"));
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
			case "type":
				return 0;
			case "value":
				return {};
			default:
				throw new Error(`Invalid member name for AttributeTypeAndValue class: ${memberName}`);
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
		//AttributeTypeAndValue ::= Sequence {
		//    type     AttributeType,
		//    value    AttributeValue }
		//
		//AttributeType ::= OBJECT IDENTIFIER
		//
		//AttributeValue ::= ANY -- DEFINED BY AttributeType

		/**
		 * @type {Object}
		 * @property {string} [blockName] Name for entire block
		 * @property {string} [type] Name for "type" element
		 * @property {string} [value] Name for "value" element
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new asn1js.Sequence({
			name: (names.blockName || ""),
			value: [
				new asn1js.ObjectIdentifier({ name: (names.type || "") }),
				new asn1js.Any({ name: (names.value || "") })
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
		/**
		 * @type {{verified: boolean}|{verified: boolean, result: {type: Object, typeValue: Object}}}
		 */
		const asn1 = asn1js.compareSchema(schema,
			schema,
			AttributeTypeAndValue.schema({
				names: {
					type: "type",
					value: "typeValue"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for ATTR_TYPE_AND_VALUE");
		//endregion

		//region Get internal properties from parsed schema
		this.type = asn1.result.type.valueBlock.toString();
		this.value = asn1.result.typeValue;
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
				new asn1js.ObjectIdentifier({ value: this.type }),
				this.value
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
		const _object = {
			type: this.type
		};

		if(Object.keys(this.value).length !== 0)
			_object.value = this.value.toJSON();
		else
			_object.value = this.value;

		return _object;
	}
	//**********************************************************************************
}
//**************************************************************************************
