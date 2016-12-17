"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _PolicyQualifierInfo = require("./PolicyQualifierInfo");

var _PolicyQualifierInfo2 = _interopRequireDefault(_PolicyQualifierInfo);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var PolicyInformation = function () {
	//**********************************************************************************
	/**
  * Constructor for PolicyInformation class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function PolicyInformation() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, PolicyInformation);

		//region Internal properties of the object
		/**
   * @type {string}
   * @description policyIdentifier
   */
		this.policyIdentifier = (0, _pvutils.getParametersValue)(parameters, "policyIdentifier", PolicyInformation.defaultValues("policyIdentifier"));

		if ("policyQualifiers" in parameters)
			/**
    * @type {Array.<PolicyQualifierInfo>}
    * @description Value of the TIME class
    */
			this.policyQualifiers = (0, _pvutils.getParametersValue)(parameters, "policyQualifiers", PolicyInformation.defaultValues("policyQualifiers"));
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


	_createClass(PolicyInformation, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, PolicyInformation.schema({
				names: {
					policyIdentifier: "policyIdentifier",
					policyQualifiers: "policyQualifiers"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for PolicyInformation");
			//endregion

			//region Get internal properties from parsed schema
			this.policyIdentifier = asn1.result.policyIdentifier.valueBlock.toString();

			if ("policyQualifiers" in asn1.result) this.policyQualifiers = Array.from(asn1.result.policyQualifiers, function (element) {
				return new _PolicyQualifierInfo2.default({ schema: element });
			});
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

			outputArray.push(new asn1js.ObjectIdentifier({ value: this.policyIdentifier }));

			if ("policyQualifiers" in this) {
				outputArray.push(new asn1js.Sequence({
					value: Array.from(this.policyQualifiers, function (element) {
						return element.toSchema();
					})
				}));
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
			var object = {
				policyIdentifier: this.policyIdentifier
			};

			if ("policyQualifiers" in this) object.policyQualifiers = Array.from(this.policyQualifiers, function (element) {
				return element.toJSON();
			});

			return object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "policyIdentifier":
					return "";
				case "policyQualifiers":
					return [];
				default:
					throw new Error("Invalid member name for PolicyInformation class: " + memberName);
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

			//PolicyInformation ::= SEQUENCE {
			//    policyIdentifier   CertPolicyId,
			//    policyQualifiers   SEQUENCE SIZE (1..MAX) OF
			//    PolicyQualifierInfo OPTIONAL }
			//
			//CertPolicyId ::= OBJECT IDENTIFIER

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [policyIdentifier]
    * @property {string} [policyQualifiers]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.ObjectIdentifier({ name: names.policyIdentifier || "" }), new asn1js.Sequence({
					optional: true,
					value: [new asn1js.Repeated({
						name: names.policyQualifiers || "",
						value: _PolicyQualifierInfo2.default.schema()
					})]
				})]
			});
		}
	}]);

	return PolicyInformation;
}();
//**************************************************************************************


exports.default = PolicyInformation;
//# sourceMappingURL=PolicyInformation.js.map