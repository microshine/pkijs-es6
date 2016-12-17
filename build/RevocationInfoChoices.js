"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _CertificateRevocationList = require("./CertificateRevocationList");

var _CertificateRevocationList2 = _interopRequireDefault(_CertificateRevocationList);

var _OtherRevocationInfoFormat = require("./OtherRevocationInfoFormat");

var _OtherRevocationInfoFormat2 = _interopRequireDefault(_OtherRevocationInfoFormat);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _toConsumableArray(arr) { if (Array.isArray(arr)) { for (var i = 0, arr2 = Array(arr.length); i < arr.length; i++) { arr2[i] = arr[i]; } return arr2; } else { return Array.from(arr); } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var RevocationInfoChoices = function () {
	//**********************************************************************************
	/**
  * Constructor for RevocationInfoChoices class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function RevocationInfoChoices() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, RevocationInfoChoices);

		//region Internal properties of the object
		/**
   * @type {Array.<CertificateRevocationList>}
   * @description crls
   */
		this.crls = (0, _pvutils.getParametersValue)(parameters, "crls", RevocationInfoChoices.defaultValues("crls"));
		/**
   * @type {Array.<OtherRevocationInfoFormat>}
   * @description otherRevocationInfos
   */
		this.otherRevocationInfos = (0, _pvutils.getParametersValue)(parameters, "otherRevocationInfos", RevocationInfoChoices.defaultValues("otherRevocationInfos"));
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


	_createClass(RevocationInfoChoices, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, RevocationInfoChoices.schema({
				names: {
					crls: "crls"
				}
			}));

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for CSM_REVOCATION_INFO_CHOICES");
			//endregion

			//region Get internal properties from parsed schema
			var _iteratorNormalCompletion = true;
			var _didIteratorError = false;
			var _iteratorError = undefined;

			try {
				for (var _iterator = asn1.result.crls[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
					var element = _step.value;

					if (element.idBlock.tagClass === 1) this.crls.push(new _CertificateRevocationList2.default({ schema: element }));else this.otherRevocationInfos.push(new _OtherRevocationInfoFormat2.default({ schema: element }));
				}

				//endregion
			} catch (err) {
				_didIteratorError = true;
				_iteratorError = err;
			} finally {
				try {
					if (!_iteratorNormalCompletion && _iterator.return) {
						_iterator.return();
					}
				} finally {
					if (_didIteratorError) {
						throw _iteratorError;
					}
				}
			}
		}
		//**********************************************************************************
		/**
   * Convert current object to asn1js object and set correct values
   * @returns {Object} asn1js object
   */

	}, {
		key: "toSchema",
		value: function toSchema() {
			//region Create array for output set
			var outputArray = [];

			outputArray.push.apply(outputArray, _toConsumableArray(Array.from(this.crls, function (element) {
				return element.toSchema();
			})));

			outputArray.push.apply(outputArray, _toConsumableArray(Array.from(this.otherRevocationInfos, function (element) {
				var schema = element.toSchema();

				schema.idBlock.tagClass = 3;
				schema.idBlock.tagNumber = 1;

				return schema;
			})));
			//endregion

			//region Construct and return new ASN.1 schema for this object
			return new asn1js.Set({
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
			return {
				crls: Array.from(this.crls, function (element) {
					return element.toJSON();
				}),
				otherRevocationInfos: Array.from(this.otherRevocationInfos, function (element) {
					return element.toJSON();
				})
			};
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "crls":
					return [];
				case "otherRevocationInfos":
					return [];
				default:
					throw new Error("Invalid member name for RevocationInfoChoices class: " + memberName);
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

			//RevocationInfoChoices ::= SET OF RevocationInfoChoice

			//RevocationInfoChoice ::= CHOICE {
			//    crl CertificateList,
			//    other [1] IMPLICIT OtherRevocationInfoFormat }

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [crls]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Set({
				name: names.blockName || "",
				value: [new asn1js.Repeated({
					name: names.crls || "",
					value: new asn1js.Choice({
						value: [_CertificateRevocationList2.default.schema(), new asn1js.Constructed({
							idBlock: {
								tagClass: 3, // CONTEXT-SPECIFIC
								tagNumber: 1 // [1]
							},
							value: [new asn1js.ObjectIdentifier(), new asn1js.Any()]
						})]
					})
				})]
			});
		}
	}]);

	return RevocationInfoChoices;
}();
//**************************************************************************************


exports.default = RevocationInfoChoices;
//# sourceMappingURL=RevocationInfoChoices.js.map