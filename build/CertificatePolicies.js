"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _PolicyInformation = require("./PolicyInformation");

var _PolicyInformation2 = _interopRequireDefault(_PolicyInformation);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var CertificatePolicies = function () {
	//**********************************************************************************
	/**
  * Constructor for CertificatePolicies class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function CertificatePolicies() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, CertificatePolicies);

		//region Internal properties of the object
		/**
   * @type {Array.<PolicyInformation>}
   * @description certificatePolicies
   */
		this.certificatePolicies = (0, _pvutils.getParametersValue)(parameters, "certificatePolicies", CertificatePolicies.defaultValues("certificatePolicies"));
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


	_createClass(CertificatePolicies, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, CertificatePolicies.schema({
				names: {
					certificatePolicies: "certificatePolicies"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for CertificatePolicies");
			//endregion

			//region Get internal properties from parsed schema
			this.certificatePolicies = Array.from(asn1.result.certificatePolicies, function (element) {
				return new _PolicyInformation2.default({ schema: element });
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
			//region Construct and return new ASN.1 schema for this object
			return new asn1js.Sequence({
				value: Array.from(this.certificatePolicies, function (element) {
					return element.toSchema();
				})
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
			return {
				certificatePolicies: Array.from(this.certificatePolicies, function (element) {
					return element.toJSON();
				})
			};
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "certificatePolicies":
					return [];
				default:
					throw new Error("Invalid member name for CertificatePolicies class: " + memberName);
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

			// CertificatePolicies OID ::= 2.5.29.32
			//
			//certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [certificatePolicies]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.Repeated({
					name: names.certificatePolicies || "",
					value: _PolicyInformation2.default.schema()
				})]
			});
		}
	}]);

	return CertificatePolicies;
}();
//**************************************************************************************


exports.default = CertificatePolicies;
//# sourceMappingURL=CertificatePolicies.js.map