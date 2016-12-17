"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _RelativeDistinguishedNames = require("./RelativeDistinguishedNames");

var _RelativeDistinguishedNames2 = _interopRequireDefault(_RelativeDistinguishedNames);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************
//region Additional asn1js schema elements existing inside GENERAL_NAME schema
//**************************************************************************************
/**
 * Schema for "builtInStandardAttributes" of "ORAddress"
 * @param {Object} parameters
 * @property {Object} [names]
 * @param {boolean} optional
 * @returns {Sequence}
 */
function builtInStandardAttributes() {
	var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];
	var optional = arguments.length <= 1 || arguments[1] === undefined ? false : arguments[1];

	//builtInStandardAttributes ::= Sequence {
	//    country-name                  CountryName OPTIONAL,
	//    administration-domain-name    AdministrationDomainName OPTIONAL,
	//    network-address           [0] IMPLICIT NetworkAddress OPTIONAL,
	//    terminal-identifier       [1] IMPLICIT TerminalIdentifier OPTIONAL,
	//    private-domain-name       [2] PrivateDomainName OPTIONAL,
	//    organization-name         [3] IMPLICIT OrganizationName OPTIONAL,
	//    numeric-user-identifier   [4] IMPLICIT NumericUserIdentifier OPTIONAL,
	//    personal-name             [5] IMPLICIT PersonalName OPTIONAL,
	//    organizational-unit-names [6] IMPLICIT OrganizationalUnitNames OPTIONAL }

	/**
  * @type {Object}
  * @property {string} [country_name]
  * @property {string} [administration_domain_name]
  * @property {string} [network_address]
  * @property {string} [terminal_identifier]
  * @property {string} [private_domain_name]
  * @property {string} [organization_name]
  * @property {string} [numeric_user_identifier]
  * @property {string} [personal_name]
  * @property {string} [organizational_unit_names]
  */
	var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

	return new asn1js.Sequence({
		optional: optional,
		value: [new asn1js.Constructed({
			optional: true,
			idBlock: {
				tagClass: 2, // APPLICATION-SPECIFIC
				tagNumber: 1 // [1]
			},
			name: names.country_name || "",
			value: [new asn1js.Choice({
				value: [new asn1js.NumericString(), new asn1js.PrintableString()]
			})]
		}), new asn1js.Constructed({
			optional: true,
			idBlock: {
				tagClass: 2, // APPLICATION-SPECIFIC
				tagNumber: 2 // [2]
			},
			name: names.administration_domain_name || "",
			value: [new asn1js.Choice({
				value: [new asn1js.NumericString(), new asn1js.PrintableString()]
			})]
		}), new asn1js.Primitive({
			optional: true,
			idBlock: {
				tagClass: 3, // CONTEXT-SPECIFIC
				tagNumber: 0 // [0]
			},
			name: names.network_address || "",
			isHexOnly: true
		}), new asn1js.Primitive({
			optional: true,
			idBlock: {
				tagClass: 3, // CONTEXT-SPECIFIC
				tagNumber: 1 // [1]
			},
			name: names.terminal_identifier || "",
			isHexOnly: true
		}), new asn1js.Constructed({
			optional: true,
			idBlock: {
				tagClass: 3, // CONTEXT-SPECIFIC
				tagNumber: 2 // [2]
			},
			name: names.private_domain_name || "",
			value: [new asn1js.Choice({
				value: [new asn1js.NumericString(), new asn1js.PrintableString()]
			})]
		}), new asn1js.Primitive({
			optional: true,
			idBlock: {
				tagClass: 3, // CONTEXT-SPECIFIC
				tagNumber: 3 // [3]
			},
			name: names.organization_name || "",
			isHexOnly: true
		}), new asn1js.Primitive({
			optional: true,
			name: names.numeric_user_identifier || "",
			idBlock: {
				tagClass: 3, // CONTEXT-SPECIFIC
				tagNumber: 4 // [4]
			},
			isHexOnly: true
		}), new asn1js.Constructed({
			optional: true,
			name: names.personal_name || "",
			idBlock: {
				tagClass: 3, // CONTEXT-SPECIFIC
				tagNumber: 5 // [5]
			},
			value: [new asn1js.Primitive({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				isHexOnly: true
			}), new asn1js.Primitive({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 1 // [1]
				},
				isHexOnly: true
			}), new asn1js.Primitive({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 2 // [2]
				},
				isHexOnly: true
			}), new asn1js.Primitive({
				optional: true,
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 3 // [3]
				},
				isHexOnly: true
			})]
		}), new asn1js.Constructed({
			optional: true,
			name: names.organizational_unit_names || "",
			idBlock: {
				tagClass: 3, // CONTEXT-SPECIFIC
				tagNumber: 6 // [6]
			},
			value: [new asn1js.Repeated({
				value: new asn1js.PrintableString()
			})]
		})]
	});
}
//**************************************************************************************
/**
 * Schema for "builtInDomainDefinedAttributes" of "ORAddress"
 * @param {boolean} optional
 * @returns {Sequence}
 */
function builtInDomainDefinedAttributes() {
	var optional = arguments.length <= 0 || arguments[0] === undefined ? false : arguments[0];

	return new asn1js.Sequence({
		optional: optional,
		value: [new asn1js.PrintableString(), new asn1js.PrintableString()]
	});
}
//**************************************************************************************
/**
 * Schema for "builtInDomainDefinedAttributes" of "ORAddress"
 * @param {boolean} optional
 * @returns {Set}
 */
function extensionAttributes() {
	var optional = arguments.length <= 0 || arguments[0] === undefined ? false : arguments[0];

	return new asn1js.Set({
		optional: optional,
		value: [new asn1js.Primitive({
			optional: true,
			idBlock: {
				tagClass: 3, // CONTEXT-SPECIFIC
				tagNumber: 0 // [0]
			},
			isHexOnly: true
		}), new asn1js.Constructed({
			optional: true,
			idBlock: {
				tagClass: 3, // CONTEXT-SPECIFIC
				tagNumber: 1 // [1]
			},
			value: [new asn1js.Any()]
		})]
	});
}
//**************************************************************************************
//endregion
//**************************************************************************************
/**
 * @class
 * @description GeneralName
 */

var GeneralName = function () {
	//**********************************************************************************
	/**
  * Constructor for GeneralName class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  * @property {number} [type] value type - from a tagged value (0 for "otherName", 1 for "rfc822Name" etc.)
  * @property {Object} [value] asn1js object having GENERAL_NAME value (type depends on "type" value)
  */

	function GeneralName() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, GeneralName);

		//region Internal properties of the object
		/**
   * @type {number}
   * @description value type - from a tagged value (0 for "otherName", 1 for "rfc822Name" etc.)
   */
		this.type = (0, _pvutils.getParametersValue)(parameters, "type", GeneralName.defaultValues("type"));
		/**
   * @type {Object}
   * @description asn1js object having GENERAL_NAME value (type depends on "type" value)
   */
		this.value = (0, _pvutils.getParametersValue)(parameters, "value", GeneralName.defaultValues("value"));
		//endregion

		//region If input argument array contains "schema" for this object
		if ("schema" in parameters) this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
  * Return default values for all class members
  * @param {string} memberName String name for a class member
  */


	_createClass(GeneralName, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, GeneralName.schema({
				names: {
					blockName: "blockName",
					otherName: "otherName",
					rfc822Name: "rfc822Name",
					dNSName: "dNSName",
					x400Address: "x400Address",
					directoryName: {
						names: {
							blockName: "directoryName"
						}
					},
					ediPartyName: "ediPartyName",
					uniformResourceIdentifier: "uniformResourceIdentifier",
					iPAddress: "iPAddress",
					registeredID: "registeredID"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for GENERAL_NAME");
			//endregion

			//region Get internal properties from parsed schema
			this.type = asn1.result.blockName.idBlock.tagNumber;

			switch (this.type) {
				case 0:
					// otherName
					this.value = asn1.result.blockName;
					break;
				case 1: // rfc822Name + dNSName + uniformResourceIdentifier
				case 2:
				case 6:
					{
						var value = asn1.result.blockName;

						value.idBlock.tagClass = 1; // UNIVERSAL
						value.idBlock.tagNumber = 22; // IA5STRING

						var valueBER = value.toBER(false);

						this.value = asn1js.fromBER(valueBER).result.valueBlock.value;
					}
					break;
				case 3:
					// x400Address
					this.value = asn1.result.blockName;
					break;
				case 4:
					// directoryName
					this.value = new _RelativeDistinguishedNames2.default({ schema: asn1.result.directoryName });
					break;
				case 5:
					// ediPartyName
					this.value = asn1.result.ediPartyName;
					break;
				case 7:
					// iPAddress
					this.value = new asn1js.OctetString({ valueHex: asn1.result.blockName.valueBlock.valueHex });
					break;
				case 8:
					// registeredID
					{
						var _value = asn1.result.blockName;

						_value.idBlock.tagClass = 1; // UNIVERSAL
						_value.idBlock.tagNumber = 6; // ObjectIdentifier

						var _valueBER = _value.toBER(false);

						this.value = asn1js.fromBER(_valueBER).result.valueBlock.toString(); // Getting a string representation of the ObjectIdentifier
					}
					break;
				default:
			}
			//endregion
		}
		//**********************************************************************************
		/**
   * Convert current object to asn1js object and set correct values
   * @returns {Object} asn1js object
   */

	}, {
		key: "toSchema",
		value: function toSchema() {
			//region Construct and return new ASN.1 schema for this object
			switch (this.type) {
				case 0:
				case 3:
				case 5:
					return new asn1js.Constructed({
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: this.type
						},
						value: [this.value]
					});
				case 1:
				case 2:
				case 6:
					{
						var value = new asn1js.IA5String({ value: this.value });

						value.idBlock.tagClass = 3;
						value.idBlock.tagNumber = this.type;

						return value;
					}
				case 4:
					return new asn1js.Constructed({
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 4
						},
						value: [this.value.toSchema()]
					});
				case 7:
					{
						var _value2 = this.value;

						_value2.idBlock.tagClass = 3;
						_value2.idBlock.tagNumber = this.type;

						return _value2;
					}
				case 8:
					{
						var _value3 = new asn1js.ObjectIdentifier({ value: this.value });

						_value3.idBlock.tagClass = 3;
						_value3.idBlock.tagNumber = this.type;

						return _value3;
					}
				default:
					return GeneralName.schema();
			}
			//endregion
		}
		//**********************************************************************************
		/**
   * Convertion for the class to JSON object
   * @returns {Object}
   */

	}, {
		key: "toJSON",
		value: function toJSON() {
			var _object = {
				type: this.type
			};

			if (typeof this.value === "string") _object.value = this.value;else _object.value = this.value.toJSON();

			return _object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "type":
					return 9;
				case "value":
					return {};
				default:
					throw new Error("Invalid member name for GeneralName class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Compare values with default values for all class members
   * @param {string} memberName String name for a class member
   * @param {*} memberValue Value to compare with default value
   */

	}, {
		key: "compareWithDefault",
		value: function compareWithDefault(memberName, memberValue) {
			switch (memberName) {
				case "type":
					return memberValue === GeneralName.defaultValues(memberName);
				case "value":
					return Object.keys(memberValue).length === 0;
				default:
					throw new Error("Invalid member name for GeneralName class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Return value of asn1js schema for current class
   * @param {Object} parameters Input parameters for the schema
   * @returns {Object} asn1js schema object
   */

	}, {
		key: "schema",
		value: function schema() {
			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

			//GeneralName ::= Choice {
			//    otherName                       [0]     OtherName,
			//    rfc822Name                      [1]     IA5String,
			//    dNSName                         [2]     IA5String,
			//    x400Address                     [3]     ORAddress,
			//    directoryName                   [4]     value,
			//    ediPartyName                    [5]     EDIPartyName,
			//    uniformResourceIdentifier       [6]     IA5String,
			//    iPAddress                       [7]     OCTET STRING,
			//    registeredID                    [8]     OBJECT IDENTIFIER }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {Object} [directoryName]
    * @property {Object} [builtInStandardAttributes]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Choice({
				value: [new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					},
					name: names.blockName || "",
					value: [new asn1js.ObjectIdentifier(), new asn1js.Constructed({
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 0 // [0]
						},
						value: [new asn1js.Any()]
					})]
				}), new asn1js.Primitive({
					name: names.blockName || "",
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					}
				}), new asn1js.Primitive({
					name: names.blockName || "",
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 2 // [2]
					}
				}), new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 3 // [3]
					},
					name: names.blockName || "",
					value: [builtInStandardAttributes(names.builtInStandardAttributes || {}, false), builtInDomainDefinedAttributes(true), extensionAttributes(true)]
				}), new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 4 // [4]
					},
					name: names.blockName || "",
					value: [_RelativeDistinguishedNames2.default.schema(names.directoryName || {})]
				}), new asn1js.Constructed({
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 5 // [5]
					},
					name: names.blockName || "",
					value: [new asn1js.Constructed({
						optional: true,
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 0 // [0]
						},
						value: [new asn1js.Choice({
							value: [new asn1js.TeletexString(), new asn1js.PrintableString(), new asn1js.UniversalString(), new asn1js.Utf8String(), new asn1js.BmpString()]
						})]
					}), new asn1js.Constructed({
						idBlock: {
							tagClass: 3, // CONTEXT-SPECIFIC
							tagNumber: 1 // [1]
						},
						value: [new asn1js.Choice({
							value: [new asn1js.TeletexString(), new asn1js.PrintableString(), new asn1js.UniversalString(), new asn1js.Utf8String(), new asn1js.BmpString()]
						})]
					})]
				}), new asn1js.Primitive({
					name: names.blockName || "",
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 6 // [6]
					}
				}), new asn1js.Primitive({
					name: names.blockName || "",
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 7 // [7]
					}
				}), new asn1js.Primitive({
					name: names.blockName || "",
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 8 // [8]
					}
				})]
			});
		}
	}]);

	return GeneralName;
}();
//**************************************************************************************


exports.default = GeneralName;
//# sourceMappingURL=GeneralName.js.map