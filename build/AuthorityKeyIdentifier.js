"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _GeneralName = require("./GeneralName");

var _GeneralName2 = _interopRequireDefault(_GeneralName);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var AuthorityKeyIdentifier = function () {
	//**********************************************************************************
	/**
  * Constructor for AuthorityKeyIdentifier class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function AuthorityKeyIdentifier() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, AuthorityKeyIdentifier);

		//region Internal properties of the object
		if ("keyIdentifier" in parameters)
			/**
    * @type {OctetString}
    * @description keyIdentifier
    */
			this.keyIdentifier = (0, _pvutils.getParametersValue)(parameters, "keyIdentifier", AuthorityKeyIdentifier.defaultValues("keyIdentifier"));

		if ("authorityCertIssuer" in parameters)
			/**
    * @type {Array.<GeneralName>}
    * @description authorityCertIssuer
    */
			this.authorityCertIssuer = (0, _pvutils.getParametersValue)(parameters, "authorityCertIssuer", AuthorityKeyIdentifier.defaultValues("authorityCertIssuer"));

		if ("authorityCertSerialNumber" in parameters)
			/**
    * @type {Integer}
    * @description authorityCertIssuer
    */
			this.authorityCertSerialNumber = (0, _pvutils.getParametersValue)(parameters, "authorityCertSerialNumber", AuthorityKeyIdentifier.defaultValues("authorityCertSerialNumber"));
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


	_createClass(AuthorityKeyIdentifier, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, AuthorityKeyIdentifier.schema({
				names: {
					keyIdentifier: "keyIdentifier",
					authorityCertIssuer: "authorityCertIssuer",
					authorityCertSerialNumber: "authorityCertSerialNumber"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for AuthorityKeyIdentifier");
			//endregion

			//region Get internal properties from parsed schema
			if ("keyIdentifier" in asn1.result) {
				asn1.result.keyIdentifier.idBlock.tagClass = 1; // UNIVERSAL
				asn1.result.keyIdentifier.idBlock.tagNumber = 4; // OCTETSTRING

				this.keyIdentifier = asn1.result.keyIdentifier;
			}

			if ("authorityCertIssuer" in asn1.result) this.authorityCertIssuer = Array.from(asn1.result.authorityCertIssuer, function (element) {
				return new _GeneralName2.default({ schema: element });
			});

			if ("authorityCertSerialNumber" in asn1.result) {
				asn1.result.authorityCertSerialNumber.idBlock.tagClass = 1; // UNIVERSAL
				asn1.result.authorityCertSerialNumber.idBlock.tagNumber = 2; // INTEGER

				this.authorityCertSerialNumber = asn1.result.authorityCertSerialNumber;
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
			//region Create array for output sequence
			var outputArray = [];

			if ("keyIdentifier" in this) {
				var value = this.keyIdentifier;

				value.idBlock.tagClass = 3; // CONTEXT-SPECIFIC
				value.idBlock.tagNumber = 0; // [0]

				outputArray.push(value);
			}

			if ("authorityCertIssuer" in this) {
				outputArray.push(new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: [new asn1js.Sequence({
						value: Array.from(this.authorityCertIssuer, function (element) {
							return element.toSchema();
						})
					})]
				}));
			}

			if ("authorityCertSerialNumber" in this) {
				var _value = this.authorityCertSerialNumber;

				_value.idBlock.tagClass = 3; // CONTEXT-SPECIFIC
				_value.idBlock.tagNumber = 2; // [2]

				outputArray.push(_value);
			}
			//endregion

			//region Construct and return new ASN.1 schema for this object
			return new asn1js.Sequence({
				value: outputArray
			});
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
			var object = {};

			if ("keyIdentifier" in this) object.keyIdentifier = this.keyIdentifier.toJSON();

			if ("authorityCertIssuer" in this) object.authorityCertIssuer = Array.from(this.authorityCertIssuer, function (element) {
				return element.toJSON();
			});

			if ("authorityCertSerialNumber" in this) object.authorityCertSerialNumber = this.authorityCertSerialNumber.toJSON();

			return object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "keyIdentifier":
					return new asn1js.OctetString();
				case "authorityCertIssuer":
					return [];
				case "authorityCertSerialNumber":
					return new asn1js.Integer();
				default:
					throw new Error("Invalid member name for AuthorityKeyIdentifier class: " + memberName);
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

			// AuthorityKeyIdentifier OID ::= 2.5.29.35
			//
			//AuthorityKeyIdentifier ::= SEQUENCE {
			//    keyIdentifier             [0] KeyIdentifier           OPTIONAL,
			//    authorityCertIssuer       [1] GeneralNames            OPTIONAL,
			//    authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
			//
			//KeyIdentifier ::= OCTET STRING

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [keyIdentifier]
    * @property {string} [authorityCertIssuer]
    * @property {string} [authorityCertSerialNumber]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.Primitive({
					name: names.keyIdentifier || "",
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 0 // [0]
					}
				}), new asn1js.Constructed({
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 1 // [1]
					},
					value: [new asn1js.Repeated({
						name: names.authorityCertIssuer || "",
						value: _GeneralName2.default.schema()
					})]
				}), new asn1js.Primitive({
					name: names.authorityCertSerialNumber || "",
					optional: true,
					idBlock: {
						tagClass: 3, // CONTEXT-SPECIFIC
						tagNumber: 2 // [2]
					}
				})]
			});
		}
	}]);

	return AuthorityKeyIdentifier;
}();
//**************************************************************************************


exports.default = AuthorityKeyIdentifier;
//# sourceMappingURL=AuthorityKeyIdentifier.js.map