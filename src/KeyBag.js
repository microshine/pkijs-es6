import PrivateKeyInfo from "./PrivateKeyInfo";
//**************************************************************************************
export default class KeyBag extends PrivateKeyInfo
{
	//**********************************************************************************
	/**
	 * Constructor for Attribute class
	 * @param {Object} [parameters={}]
	 * @property {Object} [schema] asn1js parsed value
	 */
	constructor(parameters = {})
	{
		super(parameters);
	}
	//**********************************************************************************
}
//**************************************************************************************
