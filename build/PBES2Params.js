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

var PBES2Params = function () {
	//**********************************************************************************
	/**
  * Constructor for PBES2Params class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function PBES2Params() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, PBES2Params);

		//region Internal properties of the object
		/**
   * @type {AlgorithmIdentifier}
   * @description keyDerivationFunc
   */
		this.keyDerivationFunc = (0, _pvutils.getParametersValue)(parameters, "keyDerivationFunc", PBES2Params.defaultValues("keyDerivationFunc"));
		/**
   * @type {AlgorithmIdentifier}
   * @description encryptionScheme
   */
		this.encryptionScheme = (0, _pvutils.getParametersValue)(parameters, "encryptionScheme", PBES2Params.defaultValues("encryptionScheme"));
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


	_createClass(PBES2Params, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, PBES2Params.schema({
				names: {
					keyDerivationFunc: {
						names: {
							blockName: "keyDerivationFunc"
						}
					},
					encryptionScheme: {
						names: {
							blockName: "encryptionScheme"
						}
					}
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for PBES2_params");
			//endregion

			//region Get internal properties from parsed schema
			this.keyDerivationFunc = new _AlgorithmIdentifier2.default({ schema: asn1.result.keyDerivationFunc });
			this.encryptionScheme = new _AlgorithmIdentifier2.default({ schema: asn1.result.encryptionScheme });
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
				value: [this.keyDerivationFunc.toSchema(), this.encryptionScheme.toSchema()]
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
				keyDerivationFunc: this.keyDerivationFunc.toJSON(),
				encryptionScheme: this.encryptionScheme.toJSON()
			};
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "keyDerivationFunc":
					return new _AlgorithmIdentifier2.default();
				case "encryptionScheme":
					return new _AlgorithmIdentifier2.default();
				default:
					throw new Error("Invalid member name for PBES2Params class: " + memberName);
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

			//PBES2-params ::= SEQUENCE {
			//    keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
			//    encryptionScheme AlgorithmIdentifier {{PBES2-Encs}} }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [keyDerivationFunc]
    * @property {string} [encryptionScheme]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [_AlgorithmIdentifier2.default.schema(names.keyDerivationFunc || {}), _AlgorithmIdentifier2.default.schema(names.encryptionScheme || {})]
			});
		}
	}]);

	return PBES2Params;
}();
//**************************************************************************************


exports.default = PBES2Params;
//# sourceMappingURL=PBES2Params.js.map