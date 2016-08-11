import * as asn1js from "asn1js";
import { getParametersValue } from "pvutils";
import CertificateRevocationList from "pkijs/src/CertificateRevocationList";
import OtherRevocationInfoFormat from "pkijs/src/OtherRevocationInfoFormat";
//**************************************************************************************
export default class RevocationInfoChoices
{
	//**********************************************************************************
	/**
	 * Constructor for RevocationInfoChoices class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		//region Internal properties of the object
		/**
		 * @type {Array.<CertificateRevocationList>}
		 * @description crls
		 */
		this.crls = getParametersValue(parameters, "crls", RevocationInfoChoices.defaultValues("crls"));
		/**
		 * @type {Array.<OtherRevocationInfoFormat>}
		 * @description otherRevocationInfos
		 */
		this.otherRevocationInfos = getParametersValue(parameters, "otherRevocationInfos", RevocationInfoChoices.defaultValues("otherRevocationInfos"));
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
			case "crls":
				return [];
			case "otherRevocationInfos":
				return [];
			default:
				throw new Error(`Invalid member name for RevocationInfoChoices class: ${memberName}`);
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
		//RevocationInfoChoices ::= SET OF RevocationInfoChoice

		//RevocationInfoChoice ::= CHOICE {
		//    crl CertificateList,
		//    other [1] IMPLICIT OtherRevocationInfoFormat }

		/**
		 * @type {Object}
		 * @property {string} [blockName]
		 * @property {string} [crls]
		 */
		const names = getParametersValue(parameters, "names", {});

		return (new asn1js.Set({
			name: (names.blockName || ""),
			value: [
				new asn1js.Repeated({
					name: (names.crls || ""),
					value: new asn1js.Choice({
						value: [
							CertificateRevocationList.schema(),
							new asn1js.Constructed({
								idBlock: {
									tagClass: 3, // CONTEXT-SPECIFIC
									tagNumber: 1 // [1]
								},
								value: [
									new asn1js.ObjectIdentifier(),
									new asn1js.Any()
								]
							})
						]
					})
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
			RevocationInfoChoices.schema({
				names: {
					crls: "crls"
				}
			})
		);

		if(asn1.verified === false)
			throw new Error("Object's schema was not verified against input data for CSM_REVOCATION_INFO_CHOICES");
		//endregion

		//region Get internal properties from parsed schema
		for(const element of asn1.result.crls)
		{
			if(element.idBlock.tagClass === 1)
				this.crls.push(new CertificateRevocationList({ schema: element }));
			else
				this.otherRevocationInfos.push(new OtherRevocationInfoFormat({ schema: element }));
		}

		//endregion
	}
	//**********************************************************************************
	/**
	 * Convert current object to asn1js object and set correct values
	 * @returns {Object} asn1js object
	 */
	toSchema()
	{
		//region Create array for output set
		const outputArray = [];

		outputArray.push(...Array.from(this.crls, element => element.toSchema()));

		outputArray.push(...Array.from(this.otherRevocationInfos, element => {
			const schema = element.toSchema();

			schema.idBlock.tagClass = 3;
			schema.idBlock.tagNumber = 1;

			return schema;
		}));
		//endregion
		
		//region Construct and return new ASN.1 schema for this object
		return (new asn1js.Set({
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
		return {
			crls: Array.from(this.crls, element => element.toJSON()),
			otherRevocationInfos: Array.from(this.otherRevocationInfos, element => element.toJSON())
		};
	}
	//**********************************************************************************
}
//**************************************************************************************
