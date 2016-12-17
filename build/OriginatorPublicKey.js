"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _AlgorithmIdentifier = require("./AlgorithmIdentifier");

var _AlgorithmIdentifier2 = _interopRequireDefault(_AlgorithmIdentifier);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var OriginatorPublicKey = function () {
	//**********************************************************************************
	/**
  * Constructor for OriginatorPublicKey class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function OriginatorPublicKey() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, OriginatorPublicKey);

		//region Internal properties of the object
		/**
   * @type {AlgorithmIdentifier}
   * @description algorithm
   */
		this.algorithm = (0, _pvutils.getParametersValue)(parameters, "algorithm", OriginatorPublicKey.defaultValues("algorithm"));
		/**
   * @type {BitString}
   * @description publicKey
   */
		this.publicKey = (0, _pvutils.getParametersValue)(parameters, "publicKey", OriginatorPublicKey.defaultValues("publicKey"));
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


	_createClass(OriginatorPublicKey, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, OriginatorPublicKey.schema({
				names: {
					algorithm: {
						names: {
							blockName: "algorithm"
						}
					},
					publicKey: "publicKey"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for OriginatorPublicKey");
			//endregion

			//region Get internal properties from parsed schema
			this.algorithm = new _AlgorithmIdentifier2.default({ schema: asn1.result.algorithm });
			this.publicKey = asn1.result.publicKey;
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
				value: [this.algorithm.toSchema(), this.publicKey]
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
				algorithm: this.algorithm.toJSON(),
				publicKey: this.publicKey.toJSON()
			};
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "algorithm":
					return new _AlgorithmIdentifier2.default();
				case "publicKey":
					return new asn1js.BitString();
				default:
					throw new Error("Invalid member name for OriginatorPublicKey class: " + memberName);
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
				case "algorithm":
				case "publicKey":
					return memberValue.isEqual(OriginatorPublicKey.defaultValues(memberName));
				default:
					throw new Error("Invalid member name for OriginatorPublicKey class: " + memberName);
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

			//OriginatorPublicKey ::= SEQUENCE {
			//    algorithm AlgorithmIdentifier,
			//    publicKey BIT STRING }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [algorithm]
    * @property {string} [publicKey]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [_AlgorithmIdentifier2.default.schema(names.algorithm || {}), new asn1js.BitString({ name: names.publicKey || "" })]
			});
		}
	}]);

	return OriginatorPublicKey;
}();
//**************************************************************************************


exports.default = OriginatorPublicKey;
//# sourceMappingURL=OriginatorPublicKey.js.map